// server.js

require("dotenv").config();

const express = require("express");
const mongoose = require("mongoose");
const cheerio = require("cheerio");
const dns = require("node:dns").promises;
const net = require("node:net");
const crypto = require("node:crypto");

const app = express();
const PORT = 3000;

// ============================================================
// LIMITS / SECURITY SETTINGS
// ============================================================

const MAX_LINKS = 100;
const MAX_IMAGES = 100;
const MAX_CSS = 100;
const MAX_SCRIPTS = 100;

const REQUEST_TIMEOUT = 8000;
const PAGE_TIMEOUT = 90000;

const MAX_HTML_BYTES = 5 * 1024 * 1024;
const MAX_RESPONSE_BYTES = 10 * 1024 * 1024;

const MAX_REDIRECTS = 5;
const RESOURCE_CONCURRENCY = 8;

const MAX_CONCURRENT_SCANS = 3;

const RATE_WINDOW_MS = 60 * 1000;
const MAX_SCANS_PER_WINDOW = 10;

// Maximum individual findings kept for the frontend.
// Counts are still calculated from every checked resource.
const MAX_VISIBLE_FINDINGS = 30;

// ============================================================
// IN-MEMORY JOB / RATE LIMIT STORAGE
// ============================================================

const activeJobs = new Map();
let runningScanCount = 0;
const rateBuckets = new Map();

// ============================================================
// EXPRESS
// ============================================================

app.use(express.json({ limit: "50kb" }));
app.use(express.static(__dirname));

// ============================================================
// URL VALIDATION
// ============================================================

function isValidHttpUrl(value) {
    try {
        const url = new URL(value);

        return (
            (url.protocol === "http:" || url.protocol === "https:") &&
            !!url.hostname
        );
    } catch {
        return false;
    }
}

function isHttpUrl(value) {
    return isValidHttpUrl(value);
}

function makeAbsoluteUrl(baseUrl, value) {
    try {
        return new URL(value, baseUrl).href;
    } catch {
        return null;
    }
}

// ============================================================
// IP SECURITY
// ============================================================

function isPrivateOrLocalIp(ip) {
    const normalized = String(ip)
        .toLowerCase()
        .split("%")[0];

    if (net.isIP(normalized) === 4) {
        const parts = normalized.split(".").map(Number);
        const [a, b] = parts;

        return (
            a === 0 ||
            a === 10 ||
            a === 127 ||
            (a === 100 && b >= 64 && b <= 127) ||
            (a === 169 && b === 254) ||
            (a === 172 && b >= 16 && b <= 31) ||
            (a === 192 && b === 168) ||
            (a === 198 && (b === 18 || b === 19)) ||
            (a === 198 && b === 51) ||
            (a === 203 && b === 0) ||
            a >= 224
        );
    }

    if (net.isIP(normalized) === 6) {
        const compact = normalized.replace(/^\[|\]$/g, "");

        if (compact === "::1") return true;
        if (compact === "::") return true;

        if (compact.startsWith("fe80:")) return true;

        if (
            compact.startsWith("fc") ||
            compact.startsWith("fd")
        ) {
            return true;
        }

        if (compact.startsWith("ff")) return true;

        const mapped = compact.match(
            /^::ffff:(\d+\.\d+\.\d+\.\d+)$/i
        );

        if (mapped) {
            return isPrivateOrLocalIp(mapped[1]);
        }
    }

    return false;
}

// ============================================================
// HOSTNAME SECURITY
// ============================================================

function isBlockedHostname(hostname) {
    const host = hostname
        .replace(/^\[|\]$/g, "")
        .toLowerCase();

    if (
        host === "localhost" ||
        host.endsWith(".localhost") ||
        host === "local" ||
        host.endsWith(".local") ||
        host === "metadata.google.internal" ||
        host === "metadata.google"
    ) {
        return true;
    }

    return false;
}

// ============================================================
// SAFE TARGET CHECK
// ============================================================

async function assertSafeTarget(value) {
    if (!isValidHttpUrl(value)) {
        throw new Error(
            "Only valid HTTP or HTTPS URLs are allowed."
        );
    }

    const url = new URL(value);

    const hostname = url.hostname
        .replace(/^\[|\]$/g, "")
        .toLowerCase();

    if (isBlockedHostname(hostname)) {
        throw new Error(
            "Private or local network targets are not allowed."
        );
    }

    if (net.isIP(hostname)) {
        if (isPrivateOrLocalIp(hostname)) {
            throw new Error(
                "Private or local network targets are not allowed."
            );
        }

        return true;
    }

    try {
        const addresses = await dns.lookup(hostname, {
            all: true,
            verbatim: true
        });

        if (!addresses || addresses.length === 0) {
            throw new Error(
                "The website hostname could not be resolved."
            );
        }

        const hasPrivateAddress = addresses.some(
            entry => isPrivateOrLocalIp(entry.address)
        );

        if (hasPrivateAddress) {
            throw new Error(
                "Private or local network targets are not allowed."
            );
        }

        return true;

    } catch (error) {

        if (
            error.message ===
            "Private or local network targets are not allowed."
        ) {
            throw error;
        }

        if (error.code === "ENOTFOUND") {
            throw new Error(
                "The website hostname could not be resolved."
            );
        }

        if (
            error.code === "EAI_AGAIN" ||
            error.code === "EAI_FAIL" ||
            error.code === "ESERVFAIL" ||
            error.code === "ETIMEOUT"
        ) {
            return true;
        }

        throw error;
    }
}

// ============================================================
// DELAY
// ============================================================

function sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

// ============================================================
// RETRY LOGIC
// ============================================================

function shouldRetry(status, error) {
    if (error) {
        return true;
    }

    return [
        408,
        429,
        502,
        503,
        504
    ].includes(status);
}

// ============================================================
// SAFE FETCH
// ============================================================

async function safeFetch(initialUrl, options = {}) {
    let currentUrl = initialUrl;

    const method = options.method || "GET";
    const timeoutMs = options.timeoutMs || REQUEST_TIMEOUT;
    const maxBytes = options.maxBytes || MAX_RESPONSE_BYTES;
    const allowBody = options.allowBody !== false;

    const headers = {
        "User-Agent":
            "Mozilla/5.0 (compatible; Patchkite/1.0; +https://patchkite.local)",

        "Accept":
            "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",

        ...(options.headers || {})
    };

    for (
        let redirectCount = 0;
        redirectCount <= MAX_REDIRECTS;
        redirectCount++
    ) {

        await assertSafeTarget(currentUrl);

        let lastError = null;

        for (
            let attempt = 0;
            attempt < 2;
            attempt++
        ) {

            const controller = new AbortController();

            const timeout = setTimeout(
                () => controller.abort(),
                timeoutMs
            );

            try {

                const response = await fetch(
                    currentUrl,
                    {
                        method,
                        redirect: "manual",
                        signal: controller.signal,
                        headers
                    }
                );

                clearTimeout(timeout);

                if (
                    [
                        301,
                        302,
                        303,
                        307,
                        308
                    ].includes(response.status)
                ) {

                    const location =
                        response.headers.get("location");

                    if (!location) {
                        return response;
                    }

                    if (
                        redirectCount >= MAX_REDIRECTS
                    ) {
                        throw new Error(
                            "Too many redirects."
                        );
                    }

                    const nextUrl =
                        new URL(
                            location,
                            currentUrl
                        ).href;

                    await assertSafeTarget(nextUrl);

                    currentUrl = nextUrl;

                    break;
                }

                if (
                    shouldRetry(
                        response.status,
                        null
                    ) &&
                    attempt === 0
                ) {

                    if (response.body) {
                        await response.body
                            .cancel()
                            .catch(() => {});
                    }

                    await sleep(250);

                    continue;
                }

                if (
                    allowBody &&
                    method === "GET" &&
                    response.ok
                ) {

                    const length = Number(
                        response.headers.get(
                            "content-length"
                        ) || 0
                    );

                    if (length > maxBytes) {

                        if (response.body) {
                            await response.body
                                .cancel()
                                .catch(() => {});
                        }

                        throw new Error(
                            "Response is larger than the scanner limit."
                        );
                    }
                }

                return response;

            } catch (error) {

                clearTimeout(timeout);

                lastError = error;

                if (
                    attempt === 0 &&
                    shouldRetry(null, error)
                ) {

                    await sleep(250);

                    continue;
                }

                throw error;
            }
        }

        if (lastError) {
            throw lastError;
        }
    }

    throw new Error(
        "Too many redirects."
    );
}

// ============================================================
// LIMITED RESPONSE READER
// ============================================================

async function readTextLimited(
    response,
    maxBytes
) {

    if (!response.body) {
        return "";
    }

    const reader = response.body.getReader();
    const decoder = new TextDecoder();

    const chunks = [];
    let total = 0;

    try {

        while (true) {

            const {
                done,
                value
            } = await reader.read();

            if (done) {
                break;
            }

            total += value.byteLength;

            if (total > maxBytes) {

                await reader
                    .cancel()
                    .catch(() => {});

                throw new Error(
                    "Response is larger than the scanner limit."
                );
            }

            chunks.push(
                decoder.decode(
                    value,
                    {
                        stream: true
                    }
                )
            );
        }

        chunks.push(
            decoder.decode()
        );

        return chunks.join("");

    } finally {
        reader.releaseLock();
    }
}

// ============================================================
// RESOURCE CLASSIFICATION
// ============================================================

function classifyResourceStatus(status) {

    if (
        status === 404 ||
        status === 410
    ) {
        return "confirmed";
    }

    if (
        status === 401 ||
        status === 403 ||
        status === 408 ||
        status === 429 ||
        status >= 500
    ) {
        return "review";
    }

    if (
        status >= 200 &&
        status < 400
    ) {
        return "confirmed";
    }

    if (
        status >= 400 &&
        status < 500
    ) {
        return "review";
    }

    return "review";
}

function getResourceReviewReason(status) {

    if (status === 401) {
        return "The server requires authentication or did not allow the scanner to verify this resource.";
    }

    if (status === 403) {
        return "The server denied the scanner request. This does not necessarily mean the resource is broken.";
    }

    if (status === 408) {
        return "The server timed out while processing the request.";
    }

    if (status === 429) {
        return "The server rate-limited the scanner request.";
    }

    if (status >= 500) {
        return `The resource returned HTTP ${status}.`;
    }

    if (status >= 400) {
        return `The scanner could not confirm the resource because it returned HTTP ${status}.`;
    }

    return "The scanner could not fully verify the resource.";
}

// ============================================================
// RESOURCE CHECK
// ============================================================

async function checkResource(url) {

    try {

        let response =
            await safeFetch(
                url,
                {
                    method: "HEAD",
                    timeoutMs: REQUEST_TIMEOUT,
                    allowBody: false
                }
            );

        if (
            response.status === 405 ||
            response.status === 501
        ) {

            if (response.body) {
                await response.body
                    .cancel()
                    .catch(() => {});
            }

            response =
                await safeFetch(
                    url,
                    {
                        method: "GET",
                        timeoutMs: REQUEST_TIMEOUT,
                        allowBody: false
                    }
                );

            if (response.body) {
                await response.body
                    .cancel()
                    .catch(() => {});
            }
        }

        const classification =
            classifyResourceStatus(
                response.status
            );

        return {
            ok:
                classification === "confirmed" &&
                response.status >= 200 &&
                response.status < 400,

            status:
                response.status,

            url:
                response.url || url,

            classification,

            reason:
                classification === "review"
                    ? getResourceReviewReason(
                        response.status
                    )
                    : null
        };

    } catch (error) {

        return {
            ok: false,

            status: null,

            url,

            classification: "review",

            error:
                error.name === "AbortError"
                    ? "Request timed out; the scanner could not confirm the resource."
                    : "The scanner could not confirm the resource: " +
                      error.message
        };
    }
}

// ============================================================
// RESOURCE CONCURRENCY
// ============================================================

async function checkResources(
    urls,
    concurrency = RESOURCE_CONCURRENCY
) {

    const results =
        new Array(urls.length);

    let nextIndex = 0;

    async function worker() {

        while (true) {

            const index =
                nextIndex++;

            if (index >= urls.length) {
                return;
            }

            results[index] =
                await checkResource(
                    urls[index]
                );
        }
    }

    const workerCount =
        Math.min(
            concurrency,
            urls.length
        );

    await Promise.all(
        Array.from(
            {
                length: workerCount
            },
            () => worker()
        )
    );

    return results;
}

// ============================================================
// FINDINGS
// ============================================================

function addFinding(
    findings,
    type,
    title,
    url,
    extra = {}
) {

    findings.push({
        type,
        title,
        url,
        ...extra
    });
}

// ============================================================
// FINDING AGGREGATION
// ============================================================

function createResourceSummary(
    results,
    resourceType
) {

    const summary = {
        type: resourceType,
        checked: results.length,
        confirmedBroken: 0,
        couldNotVerify: 0,
        statusCounts: {},
        affectedResources: []
    };

    for (const result of results) {

        const statusKey =
            result.status === null
                ? "error"
                : String(result.status);

        summary.statusCounts[statusKey] =
            (summary.statusCounts[statusKey] || 0) + 1;

        if (
            result.classification === "review"
        ) {

            summary.couldNotVerify++;

            summary.affectedResources.push({
                url: result.url,
                status: result.status,
                classification: "review",
                reason:
                    result.reason ||
                    result.error ||
                    "The scanner could not fully verify this resource."
            });

        } else if (!result.ok) {

            summary.confirmedBroken++;

            summary.affectedResources.push({
                url: result.url,
                status: result.status,
                classification: "confirmed",
                reason:
                    result.error ||
                    `HTTP ${result.status}`
            });
        }
    }

    return summary;
}

function addAggregatedResourceFindings(
    findings,
    summary,
    brokenType,
    brokenTitle,
    reviewTitle
) {

    for (
        const resource of summary.affectedResources
    ) {

        if (
            findings.length >=
            MAX_VISIBLE_FINDINGS
        ) {
            break;
        }

        if (
            resource.classification ===
            "confirmed"
        ) {

            addFinding(
                findings,
                brokenType,
                brokenTitle,
                resource.url,
                {
                    status: resource.status,
                    error:
                        resource.reason ||
                        "The resource returned an unsuccessful HTTP response.",
                    severity: "confirmed"
                }
            );

        } else {

            addFinding(
                findings,
                "resource-review",
                reviewTitle,
                resource.url,
                {
                    status: resource.status,
                    error: resource.reason,
                    severity: "review"
                }
            );
        }
    }
}

// ============================================================
// RATE LIMIT
// ============================================================

function isRateLimited(ip) {

    const now = Date.now();

    const existing =
        rateBuckets.get(ip) || [];

    const recent =
        existing.filter(
            timestamp =>
                now - timestamp <
                RATE_WINDOW_MS
        );

    if (
        recent.length >=
        MAX_SCANS_PER_WINDOW
    ) {

        rateBuckets.set(
            ip,
            recent
        );

        return true;
    }

    recent.push(now);

    rateBuckets.set(
        ip,
        recent
    );

    if (
        rateBuckets.size > 1000
    ) {

        for (
            const [
                key,
                timestamps
            ] of rateBuckets
        ) {

            if (
                timestamps.every(
                    timestamp =>
                        now - timestamp >=
                        RATE_WINDOW_MS
                )
            ) {

                rateBuckets.delete(key);
            }
        }
    }

    return false;
}

// ============================================================
// MAIN SCANNER
// ============================================================

async function runScan(targetUrl) {

    const controller =
        new AbortController();

    const timeout =
        setTimeout(
            () => controller.abort(),
            PAGE_TIMEOUT
        );

    try {

        await assertSafeTarget(
            targetUrl
        );

        // ====================================================
        // FETCH MAIN PAGE
        // ====================================================

        const response =
            await safeFetch(
                targetUrl,
                {
                    method: "GET",
                    timeoutMs: PAGE_TIMEOUT,
                    maxBytes: MAX_HTML_BYTES,
                    allowBody: true
                }
            );

        // ====================================================
        // MAIN PAGE STATUS
        // ====================================================

        if (!response.ok) {

            const status =
                response.status;

            // Authentication / access restriction
            // is NOT automatically a broken website.
            if (
                status === 401 ||
                status === 403 ||
                status === 429
            ) {

                return {
                    success: true,

                    scannedUrl: targetUrl,

                    finalUrl:
                        response.url || targetUrl,

                    health: {
                        status: "Could not fully verify",
                        totalIssues: 0,
                        reviewItems: 1
                    },

                    verification: {
                        status,
                        classification: "review",
                        message:
                            status === 401
                                ? "The website requires authentication or restricted the scanner request."
                                : status === 403
                                    ? "The website denied the scanner request."
                                    : "The website rate-limited the scanner request.",
                        broken: false
                    },

                    links: {
                        checked: 0,
                        broken: 0,
                        couldNotVerify: 0
                    },

                    images: {
                        checked: 0,
                        missing: 0,
                        couldNotVerify: 0
                    },

                    stylesheets: {
                        checked: 0,
                        broken: 0,
                        couldNotVerify: 0
                    },

                    scripts: {
                        checked: 0,
                        broken: 0,
                        couldNotVerify: 0
                    },

                    page: {
                        title: "",
                        titleLength: 0,
                        metaDescription: "",
                        metaDescriptionLength: 0,
                        canonical: null,
                        viewport: null,
                        robots: null,
                        h1Count: 0,
                        h2Count: 0
                    },

                    accessibility: {
                        imagesWithoutAlt: 0,
                        emptyAltImages: 0,
                        formsWithoutLabels: 0
                    },

                    security: {
                        https:
                            targetUrl.startsWith(
                                "https://"
                            ),
                        headers: {}
                    },

                    seo: {
                        issues: []
                    },

                    accessibilityScore: {
                        issues: []
                    },

                    findings: [
                        {
                            type: "verification",
                            title:
                                "Website could not be fully verified",
                            url:
                                response.url ||
                                targetUrl,
                            status,
                            severity: "review",
                            error:
                                status === 401
                                    ? "The server returned HTTP 401. This is not counted as a broken website."
                                    : status === 403
                                        ? "The server returned HTTP 403. This is not counted as a broken website."
                                        : "The server returned HTTP 429. This is not counted as a broken website."
                        }
                    ]
                };
            }

            // Genuine main-page failure.
            return {
                success: false,
                statusCode:
                    status >= 500
                        ? 502
                        : 400,
                message:
                    `Website returned HTTP ${status}.`
            };
        }

        // ====================================================
        // CONTENT TYPE
        // ====================================================

        const contentType =
            response.headers.get(
                "content-type"
            ) || "";

        if (
            !contentType
                .toLowerCase()
                .includes("text/html")
        ) {

            return {
                success: false,
                statusCode: 400,
                message:
                    "The provided URL did not return an HTML page."
            };
        }

        // ====================================================
        // READ HTML
        // ====================================================

        const html =
            await readTextLimited(
                response,
                MAX_HTML_BYTES
            );

        const $ =
            cheerio.load(html);

        const findings = [];

        let resourceWarnings = 0;

        // ====================================================
        // PAGE INFORMATION
        // ====================================================

        const pageTitle =
            $("title")
                .first()
                .text()
                .trim();

        const metaDescription =
            $('meta[name="description"]')
                .attr("content")
                ?.trim() || "";

        const canonical =
            $('link[rel="canonical"]')
                .attr("href")
                ?.trim() || null;

        const viewport =
            $('meta[name="viewport"]')
                .attr("content")
                ?.trim() || null;

        const robots =
            $('meta[name="robots"]')
                .attr("content")
                ?.trim() || null;

        const h1Count =
            $("h1").length;

        const h2Count =
            $("h2").length;

        // ====================================================
        // ACCESSIBILITY - IMAGES
        // ====================================================

        const imagesWithoutAlt =
            $("img").filter(
                function () {
                    return (
                        $(this)
                            .attr("alt") ===
                        undefined
                    );
                }
            ).length;

        const emptyAltImages =
            $("img").filter(
                function () {
                    return (
                        $(this)
                            .attr("alt") ===
                        ""
                    );
                }
            ).length;

        // ====================================================
        // ACCESSIBILITY - FORMS
        // ====================================================

        let formsWithoutLabels = 0;

        $(
            "input, select, textarea"
        ).each(
            function () {

                const element =
                    $(this);

                const type =
                    element.attr("type");

                if (
                    [
                        "hidden",
                        "submit",
                        "button",
                        "reset"
                    ].includes(type)
                ) {
                    return;
                }

                const id =
                    element.attr("id");

                const ariaLabel =
                    element.attr(
                        "aria-label"
                    );

                const ariaLabelledBy =
                    element.attr(
                        "aria-labelledby"
                    );

                let hasLabel =
                    false;

                if (
                    id &&
                    $(
                        `label[for="${id}"]`
                    ).length > 0
                ) {
                    hasLabel = true;
                }

                if (ariaLabel) {
                    hasLabel = true;
                }

                if (ariaLabelledBy) {

                    const ids =
                        ariaLabelledBy
                            .split(/\s+/)
                            .filter(Boolean);

                    if (
                        ids.length > 0 &&
                        ids.every(
                            labelId =>
                                $(
                                    `[id="${labelId}"]`
                                ).length > 0
                        )
                    ) {
                        hasLabel = true;
                    }
                }

                if (
                    element.closest(
                        "label"
                    ).length > 0
                ) {
                    hasLabel = true;
                }

                if (!hasLabel) {
                    formsWithoutLabels++;
                }
            }
        );

        // ====================================================
        // RESOURCE COLLECTION
        // ====================================================

        function collectResources(
            selector,
            attribute,
            limit
        ) {

            const items = [];
            const seen = new Set();

            $(selector).each(
                function () {

                    const value =
                        $(this).attr(
                            attribute
                        );

                    if (!value) {
                        return;
                    }

                    const absoluteUrl =
                        makeAbsoluteUrl(
                            response.url,
                            value
                        );

                    if (
                        absoluteUrl &&
                        isHttpUrl(
                            absoluteUrl
                        ) &&
                        !seen.has(
                            absoluteUrl
                        )
                    ) {

                        seen.add(
                            absoluteUrl
                        );

                        items.push(
                            absoluteUrl
                        );
                    }
                }
            );

            return items.slice(
                0,
                limit
            );
        }

        // ====================================================
        // LINKS
        // ====================================================

        const uniqueLinks =
            collectResources(
                "a[href]",
                "href",
                MAX_LINKS
            );

        // ====================================================
        // IMAGES
        // ====================================================

        const uniqueImages =
            collectResources(
                "img[src]",
                "src",
                MAX_IMAGES
            );

        // ====================================================
        // CSS
        // ====================================================

        const uniqueStylesheets =
            collectResources(
                'link[rel="stylesheet"][href]',
                "href",
                MAX_CSS
            );

        // ====================================================
        // JAVASCRIPT
        // ====================================================

        const uniqueScripts =
            collectResources(
                "script[src]",
                "src",
                MAX_SCRIPTS
            );

        // ====================================================
        // RESOURCE PROCESSOR
        // ====================================================

        async function processResources(
            urls,
            resourceType,
            brokenType,
            brokenTitle,
            reviewTitle
        ) {

            const checkedResults =
                await checkResources(
                    urls
                );

            const summary =
                createResourceSummary(
                    checkedResults,
                    resourceType
                );

            resourceWarnings +=
                summary.couldNotVerify;

            addAggregatedResourceFindings(
                findings,
                summary,
                brokenType,
                brokenTitle,
                reviewTitle
            );

            return summary;
        }

        // ====================================================
        // CHECK ALL RESOURCES
        // ====================================================

        const linkSummary =
            await processResources(
                uniqueLinks,
                "links",
                "broken-link",
                "Broken link",
                "Link could not be verified"
            );

        const imageSummary =
            await processResources(
                uniqueImages,
                "images",
                "missing-image",
                "Missing image",
                "Image could not be verified"
            );

        const stylesheetSummary =
            await processResources(
                uniqueStylesheets,
                "stylesheets",
                "broken-stylesheet",
                "Broken stylesheet",
                "Stylesheet could not be verified"
            );

        const scriptSummary =
            await processResources(
                uniqueScripts,
                "scripts",
                "broken-script",
                "Broken JavaScript file",
                "JavaScript file could not be verified"
            );

        // ====================================================
        // SEO
        // ====================================================

        const seoRecommendations = [];

        function addSeoIssue(
            message,
            title
        ) {

            seoRecommendations.push(
                message
            );

            if (
                findings.length <
                MAX_VISIBLE_FINDINGS
            ) {

                addFinding(
                    findings,
                    "seo",
                    title,
                    response.url,
                    {
                        severity:
                            "recommendation"
                    }
                );
            }
        }

        if (!pageTitle) {

            addSeoIssue(
                "Missing page title",
                "Missing page title"
            );
        }

        if (
            pageTitle.length > 60
        ) {

            addSeoIssue(
                "Page title is longer than 60 characters",
                "Page title is too long"
            );
        }

        if (!metaDescription) {

            addSeoIssue(
                "Missing meta description",
                "Missing meta description"
            );
        }

        if (
            metaDescription.length > 160
        ) {

            addSeoIssue(
                "Meta description is longer than 160 characters",
                "Meta description is too long"
            );
        }

        if (
            h1Count === 0
        ) {

            addSeoIssue(
                "No H1 heading found",
                "No H1 heading found"
            );
        }

        if (
            h1Count > 1
        ) {

            addSeoIssue(
                "Multiple H1 headings found",
                "Multiple H1 headings found"
            );
        }

        if (!canonical) {

            addSeoIssue(
                "Missing canonical URL",
                "Missing canonical URL"
            );
        }

        if (!viewport) {

            addSeoIssue(
                "Missing viewport meta tag",
                "Missing viewport meta tag"
            );
        }

        // ====================================================
        // ACCESSIBILITY FINDINGS
        // ====================================================

        const accessibilityIssues = [];

        if (
            imagesWithoutAlt > 0
        ) {

            accessibilityIssues.push(
                `${imagesWithoutAlt} image(s) missing alt text`
            );

            if (
                findings.length <
                MAX_VISIBLE_FINDINGS
            ) {

                addFinding(
                    findings,
                    "accessibility",
                    `${imagesWithoutAlt} image(s) may be missing alt text`,
                    response.url,
                    {
                        severity:
                            "confirmed"
                    }
                );
            }
        }

        if (
            formsWithoutLabels > 0
        ) {

            accessibilityIssues.push(
                `${formsWithoutLabels} form field(s) may be missing labels`
            );

            if (
                findings.length <
                MAX_VISIBLE_FINDINGS
            ) {

                addFinding(
                    findings,
                    "accessibility",
                    `${formsWithoutLabels} form field(s) may be missing labels`,
                    response.url,
                    {
                        severity:
                            "confirmed"
                    }
                );
            }
        }

        // ====================================================
        // SECURITY HEADERS
        // ====================================================

        const securityHeaders = {

            "strict-transport-security":
                response.headers.get(
                    "strict-transport-security"
                ),

            "content-security-policy":
                response.headers.get(
                    "content-security-policy"
                ),

            "x-content-type-options":
                response.headers.get(
                    "x-content-type-options"
                ),

            "x-frame-options":
                response.headers.get(
                    "x-frame-options"
                ),

            "referrer-policy":
                response.headers.get(
                    "referrer-policy"
                )
        };

        // ====================================================
        // HEALTH
        // ====================================================

        const confirmedBrokenCount =
            linkSummary.confirmedBroken +
            imageSummary.confirmedBroken +
            stylesheetSummary.confirmedBroken +
            scriptSummary.confirmedBroken;

        const totalIssues =
            confirmedBrokenCount +
            accessibilityIssues.length;

        let healthStatus =
            "Healthy";

        if (
            totalIssues > 0 &&
            totalIssues <= 3
        ) {
            healthStatus =
                "Minor issues";
        }

        if (
            totalIssues > 3
        ) {
            healthStatus =
                "Needs attention";
        }

        // ====================================================
        // FINAL RESULT
        // ====================================================

        return {

            success: true,

            scannedUrl:
                targetUrl,

            finalUrl:
                response.url,

            health: {

                status:
                    healthStatus,

                totalIssues,

                reviewItems:
                    resourceWarnings +
                    seoRecommendations.length
            },

            verification: {
                status: 200,
                classification: "confirmed",
                message:
                    "Website page was successfully fetched and analyzed.",
                broken: false
            },

            links: {

                checked:
                    linkSummary.checked,

                broken:
                    linkSummary.confirmedBroken,

                couldNotVerify:
                    linkSummary.couldNotVerify,

                statusCounts:
                    linkSummary.statusCounts
            },

            images: {

                checked:
                    imageSummary.checked,

                missing:
                    imageSummary.confirmedBroken,

                couldNotVerify:
                    imageSummary.couldNotVerify,

                statusCounts:
                    imageSummary.statusCounts
            },

            stylesheets: {

                checked:
                    stylesheetSummary.checked,

                broken:
                    stylesheetSummary.confirmedBroken,

                couldNotVerify:
                    stylesheetSummary.couldNotVerify,

                statusCounts:
                    stylesheetSummary.statusCounts
            },

            scripts: {

                checked:
                    scriptSummary.checked,

                broken:
                    scriptSummary.confirmedBroken,

                couldNotVerify:
                    scriptSummary.couldNotVerify,

                statusCounts:
                    scriptSummary.statusCounts
            },

            resourceSummary: {
                links: linkSummary,
                images: imageSummary,
                stylesheets: stylesheetSummary,
                scripts: scriptSummary
            },

            page: {

                title:
                    pageTitle,

                titleLength:
                    pageTitle.length,

                metaDescription:
                    metaDescription,

                metaDescriptionLength:
                    metaDescription.length,

                canonical:
                    canonical,

                viewport:
                    viewport,

                robots:
                    robots,

                h1Count:
                    h1Count,

                h2Count:
                    h2Count
            },

            accessibility: {

                imagesWithoutAlt:
                    imagesWithoutAlt,

                emptyAltImages:
                    emptyAltImages,

                formsWithoutLabels:
                    formsWithoutLabels
            },

            security: {

                https:
                    response.url.startsWith(
                        "https://"
                    ),

                headers:
                    securityHeaders
            },

            seo: {

                issues:
                    seoRecommendations
            },

            accessibilityScore: {

                issues:
                    accessibilityIssues
            },

            findings,

            findingsMeta: {
                visible:
                    findings.length,

                limit:
                    MAX_VISIBLE_FINDINGS,

                totalAffectedResources:
                    linkSummary.affectedResources.length +
                    imageSummary.affectedResources.length +
                    stylesheetSummary.affectedResources.length +
                    scriptSummary.affectedResources.length,

                truncated:
                    findings.length >=
                    MAX_VISIBLE_FINDINGS
            }
        };

    } catch (error) {

        if (
            error.name ===
            "AbortError"
        ) {

            return {
                success: false,
                statusCode: 504,
                message:
                    "The website took too long to respond."
            };
        }

        return {
            success: false,
            statusCode: 500,
            message:
                error.message ||
                "Something went wrong while scanning."
        };

    } finally {

        clearTimeout(timeout);
    }
}

// ============================================================
// JOB CREATION
// ============================================================

function createJob(targetUrl) {

    const id =
        crypto.randomUUID();

    const job = {

        id,

        status:
            "queued",

        createdAt:
            Date.now(),

        updatedAt:
            Date.now(),

        targetUrl,

        result:
            null
    };

    activeJobs.set(
        id,
        job
    );

    return job;
}

// ============================================================
// START JOB
// ============================================================

function startJob(job) {

    job.status =
        "scanning";

    job.updatedAt =
        Date.now();

    runningScanCount++;

    runScan(
        job.targetUrl
    )

        .then(result => {

            job.result =
                result;

            job.status =
                result.success
                    ? "completed"
                    : "failed";

            job.updatedAt =
                Date.now();
        })

        .catch(error => {

            job.status =
                "failed";

            job.result = {

                success:
                    false,

                message:
                    error.message ||
                    "Scan failed."
            };

            job.updatedAt =
                Date.now();
        })

        .finally(() => {

            runningScanCount =
                Math.max(
                    0,
                    runningScanCount - 1
                );

            setTimeout(
                () => {

                    const current =
                        activeJobs.get(
                            job.id
                        );

                    if (
                        current &&
                        Date.now() -
                        current.updatedAt >
                        15 * 60 * 1000
                    ) {

                        activeJobs.delete(
                            job.id
                        );
                    }

                },
                15 * 60 * 1000
            );
        });
}

// ============================================================
// START SCAN API
// ============================================================

app.post(
    "/api/scan",
    async (req, res) => {

        const clientIp =
            req.ip ||
            req.socket.remoteAddress ||
            "unknown";

        if (
            isRateLimited(
                clientIp
            )
        ) {

            return res.status(429).json({

                success:
                    false,

                message:
                    "Too many scans from this address. Please wait a moment and try again."
            });
        }

        if (
            runningScanCount >=
            MAX_CONCURRENT_SCANS
        ) {

            return res.status(429).json({

                success:
                    false,

                message:
                    "Patchkite is currently handling several scans. Please try again shortly."
            });
        }

        const targetUrl =
            String(
                req.body?.url || ""
            ).trim();

        if (
            !isValidHttpUrl(
                targetUrl
            )
        ) {

            return res.status(400).json({

                success:
                    false,

                message:
                    "Please enter a valid HTTP or HTTPS website URL."
            });
        }

        try {

            await assertSafeTarget(
                targetUrl
            );

        } catch (error) {

            return res.status(400).json({

                success:
                    false,

                message:
                    error.message ||
                    "The target URL is not allowed."
            });
        }

        const job =
            createJob(
                targetUrl
            );

        startJob(job);

        return res.status(202).json({

            success:
                true,

            jobId:
                job.id,

            status:
                job.status,

            message:
                "Scan started."
        });
    }
);

// ============================================================
// SCAN STATUS API
// ============================================================

app.get(
    "/api/scan/:jobId",
    (req, res) => {

        const job =
            activeJobs.get(
                req.params.jobId
            );

        if (!job) {

            return res.status(404).json({

                success:
                    false,

                message:
                    "Scan job not found or expired."
            });
        }

        if (
            job.status ===
            "completed"
        ) {

            return res.json(
                job.result
            );
        }

        if (
            job.status ===
            "failed"
        ) {

            return res.status(
                job.result?.statusCode ||
                500
            ).json({

                success:
                    false,

                message:
                    job.result?.message ||
                    "Scan failed."
            });
        }

        return res.json({

            success:
                true,

            status:
                job.status,

            jobId:
                job.id,

            message:
                job.status === "queued"
                    ? "Scan is queued."
                    : "Scan is in progress."
        });
    }
);

// ============================================================
// ROOT ROUTE
// ============================================================

app.get(
    "/",
    (req, res) => {

        res.sendFile(
            __dirname +
            "/index.html"
        );
    }
);

// ============================================================
// GRACEFUL SHUTDOWN
// ============================================================

async function shutdown(
    signal
) {

    console.log(
        `${signal} received. Shutting down Patchkite...`
    );

    try {

        await mongoose.connection.close();

        console.log(
            "MongoDB connection closed."
        );

        process.exit(0);

    } catch (error) {

        console.error(
            "Shutdown error:",
            error
        );

        process.exit(1);
    }
}

process.on(
    "SIGINT",
    () => shutdown("SIGINT")
);

process.on(
    "SIGTERM",
    () => shutdown("SIGTERM")
);

// ============================================================
// MONGODB + SERVER
// ============================================================

if (!process.env.MONGO_URI) {

    console.error(
        "MONGO_URI is missing from .env"
    );

    process.exit(1);
}

mongoose

    .connect(
        process.env.MONGO_URI
    )

    .then(() => {

        console.log(
            "MongoDB connected successfully"
        );

        app.listen(
            PORT,
            () => {

                console.log(
                    `Patchkite running at http://localhost:${PORT}`
                );
            }
        );
    })

    .catch(error => {

        console.error(
            "MongoDB connection failed:",
            error
        );

        process.exit(1);
    });