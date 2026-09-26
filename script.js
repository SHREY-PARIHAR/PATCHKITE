const scanButton = document.getElementById("scanButton");
const websiteUrl = document.getElementById("websiteUrl");
const scanStatus = document.getElementById("scanStatus");
const results = document.getElementById("results");
const findings = document.getElementById("findings");
const findingList = document.getElementById("findingList");

const totalLinks = document.getElementById("totalLinks");
const brokenLinks = document.getElementById("brokenLinks");

const totalImages = document.getElementById("totalImages");
const missingImages = document.getElementById("missingImages");

const totalStylesheets = document.getElementById("totalStylesheets");
const brokenStylesheets = document.getElementById("brokenStylesheets");

const totalScripts = document.getElementById("totalScripts");
const brokenScripts = document.getElementById("brokenScripts");

const auditOverview = document.getElementById("auditOverview");
const healthStatus = document.getElementById("healthStatus");
const healthIssues = document.getElementById("healthIssues");

const pageTitle = document.getElementById("pageTitle");
const pageTitleLength = document.getElementById("pageTitleLength");
const headingCount = document.getElementById("headingCount");
const httpsStatus = document.getElementById("httpsStatus");

const seoSection = document.getElementById("seoSection");
const seoResults = document.getElementById("seoResults");

const accessibilitySection = document.getElementById(
    "accessibilitySection"
);

const accessibilityResults = document.getElementById(
    "accessibilityResults"
);

const securitySection = document.getElementById(
    "securitySection"
);

const securityResults = document.getElementById(
    "securityResults"
);


// ============================================================
// STORAGE
// ============================================================

const STORAGE_JOB = "patchkite.activeScanJob";
const STORAGE_URL = "patchkite.activeScanUrl";
const STORAGE_REPORT = "patchkite.latestAuditReport";


// ============================================================
// GLOBAL STATE
// ============================================================

let pollTimer = null;
let currentAuditId = "";
let currentAuditDate = "";
let currentScanData = null;

// Prevent multiple polling requests from running at once.
let pollingInProgress = false;

// Number of temporary 404/network errors tolerated while polling.
let pollingErrorCount = 0;


// ============================================================
// HAPTIC FEEDBACK
// ============================================================

function hapticLight() {
    if (
        "vibrate" in navigator &&
        typeof navigator.vibrate === "function"
    ) {
        try {
            navigator.vibrate(10);
        } catch (error) {
            console.warn(
                "Light haptic feedback unavailable:",
                error
            );
        }
    }
}


function hapticShrey() {
    if (
        "vibrate" in navigator &&
        typeof navigator.vibrate === "function"
    ) {
        try {
            navigator.vibrate([45, 35, 45]);
        } catch (error) {
            console.warn(
                "SHREY haptic feedback unavailable:",
                error
            );
        }
    }
}


// ============================================================
// HIDE REPORT
// ============================================================

function hideReport() {
    if (results) {
        results.classList.add("hidden");
    }

    if (findings) {
        findings.classList.add("hidden");
    }

    if (auditOverview) {
        auditOverview.classList.add("hidden");
    }

    if (seoSection) {
        seoSection.classList.add("hidden");
    }

    if (accessibilitySection) {
        accessibilitySection.classList.add("hidden");
    }

    if (securitySection) {
        securitySection.classList.add("hidden");
    }

    const friendlySummary = document.getElementById(
        "patchkiteFriendlySummary"
    );

    if (friendlySummary) {
        friendlySummary.remove();
    }

    currentAuditId = "";
    currentAuditDate = "";
    currentScanData = null;
}


// ============================================================
// SCANNING STATUS
// ============================================================

function showScanningStatus(
    message = "Patchkite is checking the website."
) {
    if (!scanStatus) {
        return;
    }

    scanStatus.innerHTML = `
        <div class="status-icon">...</div>
        <div>
            <h3>Scanning website...</h3>
            <p>
                ${escapeHtml(message)}
            </p>
        </div>
    `;
}


// ============================================================
// FAILURE STATUS
// ============================================================

function showFailure(message) {
    if (!scanStatus) {
        return;
    }

    scanStatus.innerHTML = `
        <div class="status-icon">!</div>
        <div>
            <h3>Scan failed</h3>
            <p>
                ${escapeHtml(message)}
            </p>
        </div>
    `;
}


// ============================================================
// SAVE ACTIVE SCAN
// ============================================================

function saveActiveScan(jobId, url) {
    if (!jobId) {
        return;
    }

    localStorage.setItem(
        STORAGE_JOB,
        String(jobId)
    );

    localStorage.setItem(
        STORAGE_URL,
        String(url || "")
    );
}


// ============================================================
// CLEAR ACTIVE SCAN
// ============================================================

function clearActiveScan() {
    localStorage.removeItem(STORAGE_JOB);
    localStorage.removeItem(STORAGE_URL);
}


// ============================================================
// CREATE AUDIT ID
// ============================================================

function createAuditId() {
    const now = new Date();

    const year = String(
        now.getFullYear()
    ).slice(-2);

    const month = String(
        now.getMonth() + 1
    ).padStart(2, "0");

    const day = String(
        now.getDate()
    ).padStart(2, "0");

    const randomPart = Math.random()
        .toString(36)
        .substring(2, 7)
        .toUpperCase();

    return `PK-${year}${month}${day}-${randomPart}`;
}


// ============================================================
// CREATE AUDIT DATE
// ============================================================

function createAuditDate() {
    return new Date().toLocaleString(
        "en-IN",
        {
            day: "2-digit",
            month: "long",
            year: "numeric",
            hour: "2-digit",
            minute: "2-digit"
        }
    );
}


// ============================================================
// SCAN COMPLETED
// ============================================================

function setScanCompletedState() {
    if (!websiteUrl || !scanButton) {
        return;
    }

    websiteUrl.dataset.scanCompleted = "true";

    scanButton.textContent = "SCANNED";
    scanButton.disabled = false;
}


// ============================================================
// SCAN EDITING
// ============================================================

function setScanEditingState() {
    if (!websiteUrl) {
        return;
    }

    websiteUrl.dataset.scanCompleted = "false";

    if (
        scanButton &&
        scanButton.textContent === "SCANNED"
    ) {
        scanButton.textContent = "SCAN WEBSITE";
    }
}


// ============================================================
// START SCAN
// ============================================================

async function startWebsiteScan() {
    if (!websiteUrl || !scanButton) {
        console.error(
            "Patchkite: scan button or URL input is missing."
        );
        return;
    }

    const url = websiteUrl.value.trim();

    if (url === "") {
        alert("Please enter a website URL.");
        return;
    }

    let targetUrl = url;

    // Correct URL protocol handling.
    if (!/^https?:\/\//i.test(targetUrl)) {
        targetUrl = "https://" + targetUrl;
    }

    try {
        const parsedUrl = new URL(targetUrl);

        if (
            parsedUrl.protocol !== "http:" &&
            parsedUrl.protocol !== "https:"
        ) {
            throw new Error("Invalid protocol.");
        }
    } catch (error) {
        alert("Please enter a valid website URL.");
        return;
    }

    setScanEditingState();

    scanButton.textContent = "STARTING...";
    scanButton.disabled = true;

    hideReport();

    clearActiveScan();

    pollingErrorCount = 0;

    showScanningStatus(
        "Patchkite is starting the website scan."
    );

    try {
        const response = await fetch(
            "/api/scan",
            {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                    "Accept": "application/json"
                },
                body: JSON.stringify({
                    url: targetUrl
                }),
                cache: "no-store"
            }
        );

        let data = {};

        try {
            data = await response.json();
        } catch (error) {
            throw new Error(
                "Patchkite received an invalid response from the server."
            );
        }

        if (!response.ok) {
            throw new Error(
                data.message ||
                data.error ||
                `Unable to start the scan. Server returned HTTP ${response.status}.`
            );
        }

        if (!data.jobId) {
            // Some backends may return the completed result directly.
            if (isCompletedScanResult(data)) {
                renderScanResult(
                    data,
                    targetUrl
                );
                return;
            }

            throw new Error(
                "The scan server did not return a scan job ID."
            );
        }

        saveActiveScan(
            data.jobId,
            targetUrl
        );

        scanButton.textContent = "SCANNING...";
        scanButton.disabled = true;

        showScanningStatus(
            "You can move between Patchkite pages while the scan continues."
        );

        startPolling(
            data.jobId,
            targetUrl
        );

    } catch (error) {
        console.error(
            "Scan start error:",
            error
        );

        clearActiveScan();

        scanButton.textContent = "SCAN WEBSITE";
        scanButton.disabled = false;

        showFailure(
            error.message ||
            "Something went wrong while starting the scan."
        );
    }
}


if (scanButton && websiteUrl) {
    scanButton.addEventListener(
        "click",
        startWebsiteScan
    );
}


// ============================================================
// ENTER KEY = START SCAN
// ============================================================

if (websiteUrl) {
    websiteUrl.addEventListener(
        "keydown",
        function (event) {
            if (
                event.key === "Enter" &&
                !event.shiftKey
            ) {
                event.preventDefault();

                if (
                    scanButton &&
                    !scanButton.disabled &&
                    websiteUrl.value.trim() !== ""
                ) {
                    startWebsiteScan();
                }
            }
        }
    );
}


// ============================================================
// CHECK WHETHER RESPONSE IS A COMPLETED SCAN
// ============================================================

function isCompletedScanResult(data) {
    if (!data || typeof data !== "object") {
        return false;
    }

    // Explicit completed status.
    if (
        data.status === "completed" ||
        data.status === "complete" ||
        data.status === "finished" ||
        data.status === "done"
    ) {
        return true;
    }

    // Existing Patchkite response structure.
    if (
        data.links &&
        data.page &&
        data.security
    ) {
        return true;
    }

    return false;
}


// ============================================================
// START POLLING
// ============================================================

function startPolling(
    jobId,
    targetUrl
) {
    stopPolling();

    pollingErrorCount = 0;
    pollingInProgress = false;

    // Check immediately.
    pollScanJob(
        jobId,
        targetUrl
    );

    pollTimer = setInterval(
        function () {
            pollScanJob(
                jobId,
                targetUrl
            );
        },
        1200
    );
}


// ============================================================
// STOP POLLING
// ============================================================

function stopPolling() {
    if (pollTimer) {
        clearInterval(pollTimer);
        pollTimer = null;
    }

    pollingInProgress = false;
}


// ============================================================
// RESET SCAN UI
// ============================================================

function resetScanButton() {
    if (scanButton) {
        scanButton.textContent = "SCAN WEBSITE";
        scanButton.disabled = false;
    }

    if (websiteUrl) {
        websiteUrl.dataset.scanCompleted = "false";
    }
}


// ============================================================
// CHECK SCAN STATUS
// ============================================================

async function pollScanJob(
    jobId,
    targetUrl
) {
    // Do not create overlapping polling requests.
    if (pollingInProgress) {
        return;
    }

    if (!jobId) {
        stopPolling();
        clearActiveScan();
        resetScanButton();

        showFailure(
            "The scan job ID is missing. Please start a new scan."
        );

        return;
    }

    pollingInProgress = true;

    try {
        const response = await fetch(
            `/api/scan/${encodeURIComponent(jobId)}`,
            {
                method: "GET",
                headers: {
                    "Accept": "application/json"
                },
                cache: "no-store"
            }
        );

        let data = {};

        try {
            data = await response.json();
        } catch (error) {
            data = {};
        }


        // ----------------------------------------------------
        // COMPLETED RESULT ALWAYS WINS
        // ----------------------------------------------------

        if (
            response.ok &&
            isCompletedScanResult(data)
        ) {
            pollingErrorCount = 0;

            stopPolling();
            clearActiveScan();

            renderScanResult(
                data,
                targetUrl
            );

            return;
        }


        // ----------------------------------------------------
        // 404 HANDLING
        // ----------------------------------------------------
        //
        // IMPORTANT:
        // A temporary 404 must NOT instantly show
        // "scan expired".
        //
        // We retry several times because:
        // - backend may still be creating the job
        // - serverless route may wake up slowly
        // - deployment can briefly return 404
        // - job store may not be immediately available
        //

        if (response.status === 404) {
            pollingErrorCount++;

            console.warn(
                `Patchkite polling returned 404. Retry ${pollingErrorCount}/15.`
            );

            showScanningStatus(
                "Patchkite is waiting for the scan server..."
            );

            // Keep polling instead of immediately failing.
            //
            // Only after many consecutive 404 responses do we
            // stop and ask for a new scan.
            if (pollingErrorCount >= 15) {
                stopPolling();
                clearActiveScan();
                resetScanButton();

                showFailure(
                    "The scan server is not responding. Please start the scan again."
                );
            }

            return;
        }


        // ----------------------------------------------------
        // OTHER SERVER ERRORS
        // ----------------------------------------------------

        if (!response.ok) {
            pollingErrorCount++;

            console.warn(
                "Patchkite scan status error:",
                response.status,
                data
            );

            showScanningStatus(
                "Patchkite is reconnecting to the scan server..."
            );

            // Temporary server/network problem:
            // keep retrying.
            if (pollingErrorCount >= 20) {
                stopPolling();
                clearActiveScan();
                resetScanButton();

                showFailure(
                    data.message ||
                    data.error ||
                    "The scan server is not responding."
                );
            }

            return;
        }


        // Successful response resets temporary error count.
        pollingErrorCount = 0;


        // ----------------------------------------------------
        // QUEUED
        // ----------------------------------------------------

        if (
            data.status === "queued" ||
            data.status === "pending" ||
            data.status === "waiting"
        ) {
            showScanningStatus(
                "Your scan is queued and will start shortly."
            );

            return;
        }


        // ----------------------------------------------------
        // RUNNING
        // ----------------------------------------------------

        if (
            data.status === "running" ||
            data.status === "scanning" ||
            data.status === "processing"
        ) {
            showScanningStatus(
                "Patchkite is checking the website."
            );

            return;
        }


        // ----------------------------------------------------
        // FAILED
        // ----------------------------------------------------

        if (
            data.status === "failed" ||
            data.status === "error"
        ) {
            stopPolling();
            clearActiveScan();
            resetScanButton();

            showFailure(
                data.message ||
                data.error ||
                "The website scan could not be completed."
            );

            return;
        }


        // ----------------------------------------------------
        // UNKNOWN BUT VALID RESPONSE
        // ----------------------------------------------------

        showScanningStatus(
            "Patchkite is checking the website."
        );

    } catch (error) {
        pollingErrorCount++;

        console.warn(
            "Scan status check failed:",
            error
        );

        // Do NOT kill the scan for one network failure.
        showScanningStatus(
            "Patchkite is reconnecting to the scan server..."
        );

        if (pollingErrorCount >= 20) {
            stopPolling();
            clearActiveScan();
            resetScanButton();

            showFailure(
                "Patchkite could not reconnect to the scan server."
            );
        }

    } finally {
        pollingInProgress = false;
    }
}


// ============================================================
// RENDER SCAN RESULT
// ============================================================

function renderScanResult(
    data,
    targetUrl
) {
    currentScanData = data;

    currentAuditId = createAuditId();
    currentAuditDate = createAuditDate();


    // --------------------------------------------------------
    // SAVE REPORT
    // --------------------------------------------------------

    const reportData = {
        auditId: currentAuditId,
        auditDate: currentAuditDate,
        scannedUrl:
            data.scannedUrl ||
            targetUrl ||
            (websiteUrl ? websiteUrl.value : ""),
        data: data
    };

    localStorage.setItem(
        STORAGE_REPORT,
        JSON.stringify(reportData)
    );


    // --------------------------------------------------------
    // STATUS
    // --------------------------------------------------------

    if (scanStatus) {
        scanStatus.innerHTML = `
            <div class="status-icon">✓</div>
            <div>
                <h3>Scan completed</h3>
                <p>
                    Patchkite has finished checking the website.
                </p>
            </div>
        `;
    }


    // --------------------------------------------------------
    // RESULTS
    // --------------------------------------------------------

    if (results) {
        results.classList.remove("hidden");
    }

    if (totalLinks) {
        totalLinks.textContent =
            data.links?.checked ?? 0;
    }

    if (brokenLinks) {
        brokenLinks.textContent =
            data.links?.broken ?? 0;
    }

    if (totalImages) {
        totalImages.textContent =
            data.images?.checked ?? 0;
    }

    if (missingImages) {
        missingImages.textContent =
            data.images?.missing ?? 0;
    }

    if (totalStylesheets) {
        totalStylesheets.textContent =
            data.stylesheets?.checked ?? 0;
    }

    if (brokenStylesheets) {
        brokenStylesheets.textContent =
            data.stylesheets?.broken ?? 0;
    }

    if (totalScripts) {
        totalScripts.textContent =
            data.scripts?.checked ?? 0;
    }

    if (brokenScripts) {
        brokenScripts.textContent =
            data.scripts?.broken ?? 0;
    }


    // --------------------------------------------------------
    // HEALTH
    // --------------------------------------------------------

    if (auditOverview) {
        auditOverview.classList.remove("hidden");
    }

    if (healthStatus) {
        healthStatus.textContent =
            data.health?.status ?? "Unknown";
    }

    const confirmedIssues = Number(
        data.health?.totalIssues ?? 0
    );

    const reviewItems = Number(
        data.health?.reviewItems ?? 0
    );

    if (healthIssues) {
        healthIssues.textContent =
            reviewItems > 0
                ? `${confirmedIssues} issue(s) detected • ${reviewItems} review item(s)`
                : `${confirmedIssues} issue(s) detected`;
    }


    // --------------------------------------------------------
    // PAGE
    // --------------------------------------------------------

    if (pageTitle) {
        pageTitle.textContent =
            data.page?.title ||
            "No title";
    }

    if (pageTitleLength) {
        pageTitleLength.textContent =
            `${data.page?.titleLength ?? 0} characters`;
    }

    if (headingCount) {
        headingCount.textContent =
            `${data.page?.h1Count ?? 0} H1 / ${data.page?.h2Count ?? 0} H2`;
    }

    if (httpsStatus) {
        httpsStatus.textContent =
            data.security?.https
                ? "Secure"
                : "Not secure";
    }


    // ========================================================
    // SEO
    // ========================================================

    if (seoSection) {
        seoSection.classList.remove("hidden");
    }

    let seoIssues =
        data.seo?.issues ?? [];

    if (!Array.isArray(seoIssues)) {
        seoIssues = [
            String(seoIssues)
        ];
    }

    if (seoResults) {
        if (seoIssues.length === 0) {
            seoResults.innerHTML = `
                <div class="audit-item success">
                    <strong>
                        ✓ SEO checks passed
                    </strong>
                    <small>
                        No major SEO issues were detected.
                    </small>
                </div>
            `;
        } else {
            seoResults.innerHTML =
                seoIssues
                    .map(function (issue) {
                        return `
                            <div class="audit-item warning">
                                <strong>
                                    ⚠ ${escapeHtml(issue)}
                                </strong>
                                <small>
                                    Review this SEO element.
                                </small>
                            </div>
                        `;
                    })
                    .join("");
        }
    }


    // ========================================================
    // ACCESSIBILITY
    // ========================================================

    if (accessibilitySection) {
        accessibilitySection.classList.remove("hidden");
    }

    const accessibility =
        data.accessibility ?? {};

    if (accessibilityResults) {
        accessibilityResults.innerHTML = `
            <div class="audit-item ${
                accessibility.imagesWithoutAlt > 0
                    ? "warning"
                    : "success"
            }">
                <strong>
                    ${
                        accessibility.imagesWithoutAlt > 0
                            ? "⚠"
                            : "✓"
                    }
                    ${
                        accessibility.imagesWithoutAlt ?? 0
                    }
                    images missing alt text
                </strong>
                <small>
                    Images that may need descriptive alternative text.
                </small>
            </div>

            <div class="audit-item ${
                accessibility.emptyAltImages > 0
                    ? "warning"
                    : "success"
            }">
                <strong>
                    ${
                        accessibility.emptyAltImages > 0
                            ? "⚠"
                            : "✓"
                    }
                    ${
                        accessibility.emptyAltImages ?? 0
                    }
                    empty alt attributes
                </strong>
                <small>
                    Images using an empty alt attribute.
                </small>
            </div>

            <div class="audit-item ${
                accessibility.formsWithoutLabels > 0
                    ? "warning"
                    : "success"
            }">
                <strong>
                    ${
                        accessibility.formsWithoutLabels > 0
                            ? "⚠"
                            : "✓"
                    }
                    ${
                        accessibility.formsWithoutLabels ?? 0
                    }
                    form fields without labels
                </strong>
                <small>
                    Form controls that may need accessible labels.
                </small>
            </div>
        `;
    }


    // ========================================================
    // SECURITY
    // ========================================================

    if (securitySection) {
        securitySection.classList.remove("hidden");
    }

    const securityHeaders =
        data.security?.headers ?? {};

    if (securityResults) {
        securityResults.innerHTML = `
            ${securityHeader(
                "Strict-Transport-Security",
                securityHeaders[
                    "strict-transport-security"
                ]
            )}

            ${securityHeader(
                "Content-Security-Policy",
                securityHeaders[
                    "content-security-policy"
                ]
            )}

            ${securityHeader(
                "X-Content-Type-Options",
                securityHeaders[
                    "x-content-type-options"
                ]
            )}

            ${securityHeader(
                "X-Frame-Options",
                securityHeaders[
                    "x-frame-options"
                ]
            )}

            ${securityHeader(
                "Referrer-Policy",
                securityHeaders[
                    "referrer-policy"
                ]
            )}
        `;
    }


    // ========================================================
    // FINDINGS
    // ========================================================

    if (findings) {
        findings.classList.remove("hidden");
    }

    const allFindings =
        Array.isArray(data.findings)
            ? data.findings
            : [];

    if (findingList) {
        if (allFindings.length === 0) {
            findingList.innerHTML = `
                <div class="finding">
                    <strong>
                        ✓ No problems found
                    </strong>
                    <small>
                        Patchkite did not find any major issues on this page.
                    </small>
                </div>
            `;
        } else {
            findingList.innerHTML =
                allFindings
                    .map(function (finding) {
                        let icon = "⚠️";

                        if (
                            finding.type ===
                            "broken-link"
                        ) {
                            icon = "🔗";
                        }

                        if (
                            finding.type ===
                            "missing-image"
                        ) {
                            icon = "🖼️";
                        }

                        if (
                            finding.type ===
                            "broken-stylesheet"
                        ) {
                            icon = "🎨";
                        }

                        if (
                            finding.type ===
                            "broken-script"
                        ) {
                            icon = "JS";
                        }

                        if (
                            finding.type ===
                            "seo"
                        ) {
                            icon = "SEO";
                        }

                        if (
                            finding.type ===
                            "accessibility"
                        ) {
                            icon = "♿";
                        }

                        return `
                            <div class="finding">
                                <strong>
                                    ${icon}
                                    ${escapeHtml(
                                        finding.title ||
                                        "Finding"
                                    )}
                                </strong>

                                <small>
                                    ${escapeHtml(
                                        finding.url ||
                                        ""
                                    )}

                                    ${
                                        finding.status
                                            ? ` → HTTP ${escapeHtml(
                                                String(
                                                    finding.status
                                                )
                                            )}`
                                            : ""
                                    }

                                    ${
                                        finding.error
                                            ? ` → ${escapeHtml(
                                                finding.error
                                            )}`
                                            : ""
                                    }
                                </small>
                            </div>
                        `;
                    })
                    .join("");
        }
    }


    // --------------------------------------------------------
    // KEEP CURRENT URL AFTER SCAN
    // --------------------------------------------------------

    if (websiteUrl) {
        websiteUrl.value =
            data.scannedUrl ||
            targetUrl ||
            websiteUrl.value;
    }


    // --------------------------------------------------------
    // FRIENDLY SUMMARY
    // --------------------------------------------------------

    renderFriendlySummary(data);


    // --------------------------------------------------------
    // COMPLETE
    // --------------------------------------------------------

    setScanCompletedState();
}


// ============================================================
// FRIENDLY SUMMARY
// ============================================================

function renderFriendlySummary(data) {
    let summary =
        document.getElementById(
            "patchkiteFriendlySummary"
        );

    if (!summary) {
        summary =
            document.createElement("div");

        summary.id =
            "patchkiteFriendlySummary";

        const auditOverviewElement =
            document.getElementById(
                "auditOverview"
            );

        if (auditOverviewElement) {
            auditOverviewElement.parentNode.insertBefore(
                summary,
                auditOverviewElement
            );
        } else {
            document.body.appendChild(summary);
        }
    }

    const confirmedIssues =
        Number(
            data.health?.totalIssues ?? 0
        );

    const reviewItems =
        Number(
            data.health?.reviewItems ?? 0
        );

    const brokenLinksCount =
        Number(
            data.links?.broken ?? 0
        );

    const missingImagesCount =
        Number(
            data.images?.missing ?? 0
        );

    const brokenCssCount =
        Number(
            data.stylesheets?.broken ?? 0
        );

    const brokenJsCount =
        Number(
            data.scripts?.broken ?? 0
        );

    const seoIssues =
        Array.isArray(data.seo?.issues)
            ? data.seo.issues.length
            : 0;

    const accessibility =
        data.accessibility ?? {};

    const accessibilityIssues =
        Number(
            accessibility.imagesWithoutAlt ?? 0
        ) +
        Number(
            accessibility.formsWithoutLabels ?? 0
        );

    const totalProblems =
        confirmedIssues +
        brokenLinksCount +
        missingImagesCount +
        brokenCssCount +
        brokenJsCount +
        seoIssues +
        accessibilityIssues;

    let title = "";
    let message = "";
    let className = "";

    if (
        confirmedIssues >= 5 ||
        brokenLinksCount >= 5 ||
        brokenCssCount >= 3 ||
        brokenJsCount >= 3
    ) {
        className = "serious";

        title =
            "Website needs maintenance";

        message =
            "Website needs maintenance, with multiple issues affecting important resources.";

    } else if (
        totalProblems > 0 ||
        reviewItems > 0
    ) {
        className = "minor";

        title =
            "Website is working, but some areas need attention.";

        message =
            `Patchkite found ${confirmedIssues} confirmed issue(s) and ${reviewItems} item(s) that could not be fully confirmed.`;

    } else {
        className = "clean";

        title =
            "Website is working well and no major issues were found.";

        message =
            "Patchkite completed the available website scan successfully.";
    }

    summary.className =
        "patchkite-friendly-summary " +
        className;

    summary.innerHTML = `
        <div class="friendly-summary-inner">

            <div class="friendly-summary-label">
                PATCHKITE WEBSITE STATUS
            </div>

            <h3>
                ${escapeHtml(title)}
            </h3>

            <p>
                ${escapeHtml(message)}
            </p>

            <div class="patchkite-audit-meta">

                <div class="patchkite-audit-meta-item">
                    <span>
                        AUDIT ID
                    </span>

                    <strong>
                        ${escapeHtml(currentAuditId)}
                    </strong>
                </div>

                <div class="patchkite-audit-meta-item">
                    <span>
                        AUDITED
                    </span>

                    <strong>
                        ${escapeHtml(currentAuditDate)}
                    </strong>
                </div>

            </div>

            <div class="patchkite-report-actions">

                <button
                    type="button"
                    class="patchkite-copy-report"
                    id="patchkiteCopyReport"
                >
                    COPY REPORT
                </button>

                <button
                    type="button"
                    class="patchkite-view-report"
                    id="patchkiteViewReport"
                >
                    VIEW FULL REPORT
                </button>

            </div>

            <small>
                Confirmed issues are shown separately from items that Patchkite could not fully confirm.
            </small>

        </div>
    `;


    const copyButton =
        document.getElementById(
            "patchkiteCopyReport"
        );

    if (copyButton) {
        copyButton.addEventListener(
            "click",
            async function () {
                hapticLight();

                await copyAuditReport(data);
            }
        );
    }


    const viewReportButton =
        document.getElementById(
            "patchkiteViewReport"
        );

    if (viewReportButton) {
        viewReportButton.addEventListener(
            "click",
            function () {
                hapticLight();

                openFullAuditReport(data);
            }
        );
    }
}


// ============================================================
// OPEN FULL REPORT
// ============================================================

function openFullAuditReport(data) {
    const reportData = {
        auditId: currentAuditId,
        auditDate: currentAuditDate,
        scannedUrl:
            data.scannedUrl ||
            (websiteUrl ? websiteUrl.value : ""),
        data: data
    };

    localStorage.setItem(
        STORAGE_REPORT,
        JSON.stringify(reportData)
    );

    // Always open report.html from website root.
    window.location.assign("/report.html");
}


// ============================================================
// BUILD COPY REPORT
// ============================================================

function buildCopyReport(data) {
    const confirmedIssues =
        Number(
            data.health?.totalIssues ?? 0
        );

    const reviewItems =
        Number(
            data.health?.reviewItems ?? 0
        );

    const allFindings =
        Array.isArray(data.findings)
            ? data.findings
            : [];

    const lines = [];

    lines.push(
        "PATCHKITE — WEBSITE AUDIT"
    );

    lines.push("");

    lines.push(
        `AUDIT ID: ${currentAuditId}`
    );

    lines.push(
        `AUDITED: ${currentAuditDate}`
    );

    lines.push(
        `WEBSITE: ${
            data.scannedUrl ||
            (websiteUrl ? websiteUrl.value : "")
        }`
    );

    lines.push("");

    lines.push(
        "WEBSITE STATUS"
    );

    lines.push(
        `Overall health: ${
            data.health?.status ||
            "Unknown"
        }`
    );

    lines.push(
        `Confirmed issues: ${confirmedIssues}`
    );

    lines.push(
        `Needs review: ${reviewItems}`
    );

    lines.push("");

    lines.push(
        "TECHNICAL OVERVIEW"
    );

    lines.push(
        `Links checked: ${
            data.links?.checked ?? 0
        }`
    );

    lines.push(
        `Broken links: ${
            data.links?.broken ?? 0
        }`
    );

    lines.push(
        `Images checked: ${
            data.images?.checked ?? 0
        }`
    );

    lines.push(
        `Missing images: ${
            data.images?.missing ?? 0
        }`
    );

    lines.push(
        `CSS files checked: ${
            data.stylesheets?.checked ?? 0
        }`
    );

    lines.push(
        `Broken CSS: ${
            data.stylesheets?.broken ?? 0
        }`
    );

    lines.push(
        `JS files checked: ${
            data.scripts?.checked ?? 0
        }`
    );

    lines.push(
        `Broken JS: ${
            data.scripts?.broken ?? 0
        }`
    );

    lines.push("");

    lines.push("PAGE");

    lines.push(
        `Title: ${
            data.page?.title ||
            "No title"
        }`
    );

    lines.push(
        `Title length: ${
            data.page?.titleLength ?? 0
        } characters`
    );

    lines.push(
        `Headings: ${
            data.page?.h1Count ?? 0
        } H1 / ${
            data.page?.h2Count ?? 0
        } H2`
    );

    lines.push(
        `HTTPS: ${
            data.security?.https
                ? "Secure"
                : "Not secure"
        }`
    );

    lines.push("");

    lines.push("SEO");

    const seoIssues =
        Array.isArray(data.seo?.issues)
            ? data.seo.issues
            : [];

    if (seoIssues.length === 0) {
        lines.push(
            "SEO checks passed."
        );
    } else {
        seoIssues.forEach(
            function (issue) {
                lines.push(
                    `- ${issue}`
                );
            }
        );
    }

    lines.push("");

    lines.push(
        "ACCESSIBILITY"
    );

    const accessibility =
        data.accessibility ?? {};

    lines.push(
        `Images missing alt text: ${
            accessibility.imagesWithoutAlt ?? 0
        }`
    );

    lines.push(
        `Empty alt attributes: ${
            accessibility.emptyAltImages ?? 0
        }`
    );

    lines.push(
        `Form fields without labels: ${
            accessibility.formsWithoutLabels ?? 0
        }`
    );

    lines.push("");

    lines.push(
        "SECURITY HEADERS"
    );

    const securityHeaders =
        data.security?.headers ?? {};

    [
        "strict-transport-security",
        "content-security-policy",
        "x-content-type-options",
        "x-frame-options",
        "referrer-policy"
    ].forEach(
        function (header) {
            lines.push(
                `${header}: ${
                    securityHeaders[header]
                        ? "Detected"
                        : "Not detected"
                }`
            );
        }
    );

    lines.push("");

    lines.push("FINDINGS");

    if (allFindings.length === 0) {
        lines.push(
            "No major findings."
        );
    } else {
        allFindings.forEach(
            function (finding) {
                let line =
                    `- ${
                        finding.title ||
                        "Finding"
                    }`;

                if (finding.url) {
                    line +=
                        ` — ${finding.url}`;
                }

                if (finding.status) {
                    line +=
                        ` — HTTP ${finding.status}`;
                }

                if (finding.error) {
                    line +=
                        ` — ${finding.error}`;
                }

                lines.push(line);
            }
        );
    }

    lines.push("");

    lines.push(
        "Audited by PATCHKITE."
    );

    return lines.join("\n");
}


// ============================================================
// COPY REPORT
// ============================================================

async function copyAuditReport(data) {
    const report =
        buildCopyReport(data);

    const copyButton =
        document.getElementById(
            "patchkiteCopyReport"
        );

    try {
        if (
            navigator.clipboard &&
            navigator.clipboard.writeText
        ) {
            await navigator.clipboard.writeText(
                report
            );
        } else {
            const textarea =
                document.createElement(
                    "textarea"
                );

            textarea.value = report;

            textarea.style.position = "fixed";
            textarea.style.opacity = "0";

            document.body.appendChild(
                textarea
            );

            textarea.select();

            document.execCommand("copy");

            textarea.remove();
        }

        if (copyButton) {
            const originalText =
                copyButton.textContent;

            copyButton.textContent = "COPIED";

            setTimeout(
                function () {
                    copyButton.textContent =
                        originalText;
                },
                1600
            );
        }

    } catch (error) {
        console.error(
            "Copy report failed:",
            error
        );

        if (copyButton) {
            copyButton.textContent =
                "COPY FAILED";

            setTimeout(
                function () {
                    copyButton.textContent =
                        "COPY REPORT";
                },
                1800
            );
        }
    }
}


// ============================================================
// SECURITY HEADER
// ============================================================

function securityHeader(
    name,
    value
) {
    if (value) {
        return `
            <div class="audit-item success">
                <strong>
                    ✓ ${escapeHtml(name)}
                </strong>

                <small>
                    Header detected
                </small>
            </div>
        `;
    }

    return `
        <div class="audit-item warning">
            <strong>
                ⚠ ${escapeHtml(name)}
            </strong>

            <small>
                Header not detected
            </small>
        </div>
    `;
}


// ============================================================
// HTML ESCAPE
// ============================================================

function escapeHtml(value) {
    return String(value)
        .replace(
            /&/g,
            "&amp;"
        )
        .replace(
            /</g,
            "&lt;"
        )
        .replace(
            />/g,
            "&gt;"
        )
        .replace(
            /"/g,
            "&quot;"
        )
        .replace(
            /'/g,
            "&#039;"
        );
}


// ============================================================
// SEARCH BAR
// ============================================================

if (websiteUrl) {
    websiteUrl.type = "search";

    websiteUrl.setAttribute(
        "autocomplete",
        "off"
    );

    websiteUrl.setAttribute(
        "autocapitalize",
        "none"
    );

    websiteUrl.setAttribute(
        "spellcheck",
        "false"
    );
}


// ============================================================
// SELECT FULL WEBSITE URL
// ============================================================

function selectFullWebsiteUrl() {
    if (
        !websiteUrl ||
        websiteUrl.dataset.scanCompleted !==
            "true"
    ) {
        return;
    }

    requestAnimationFrame(
        function () {
            websiteUrl.focus({
                preventScroll: true
            });

            websiteUrl.select();

            if (
                typeof websiteUrl.setSelectionRange ===
                "function"
            ) {
                websiteUrl.setSelectionRange(
                    0,
                    websiteUrl.value.length
                );
            }
        }
    );
}


if (websiteUrl) {
    websiteUrl.addEventListener(
        "focus",
        function () {
            if (
                websiteUrl.dataset.scanCompleted ===
                "true"
            ) {
                selectFullWebsiteUrl();
            }
        }
    );

    websiteUrl.addEventListener(
        "click",
        function () {
            if (
                websiteUrl.dataset.scanCompleted ===
                "true"
            ) {
                selectFullWebsiteUrl();
            }
        }
    );

    websiteUrl.addEventListener(
        "touchend",
        function () {
            if (
                websiteUrl.dataset.scanCompleted ===
                "true"
            ) {
                setTimeout(
                    selectFullWebsiteUrl,
                    0
                );
            }
        },
        {
            passive: true
        }
    );

    websiteUrl.addEventListener(
        "input",
        function () {
            setScanEditingState();
        }
    );
}


// ============================================================
// NAVIGATION FEEDBACK
// ============================================================

document.querySelectorAll(
    ".navbar nav a"
).forEach(
    function (link) {
        link.addEventListener(
            "pointerdown",
            function () {
                link.style.transform =
                    "scale(0.94)";
            }
        );

        link.addEventListener(
            "pointerup",
            function () {
                link.style.transform = "";
            }
        );

        link.addEventListener(
            "pointercancel",
            function () {
                link.style.transform = "";
            }
        );

        link.addEventListener(
            "click",
            function () {
                const linkText =
                    (link.textContent || "")
                        .trim()
                        .toLowerCase();

                if (linkText === "shrey") {
                    hapticShrey();
                } else {
                    hapticLight();
                }
            }
        );
    }
);


// ============================================================
// EXTRA SHREY HAPTIC DETECTION
// ============================================================

document.querySelectorAll(
    "a, button"
).forEach(
    function (element) {
        const text =
            (element.textContent || "")
                .trim()
                .toLowerCase();

        if (
            text === "shrey" &&
            !element.closest(".navbar nav")
        ) {
            element.addEventListener(
                "click",
                function () {
                    hapticShrey();
                }
            );
        }
    }
);


// ============================================================
// COPY REPORT HAPTIC
// ============================================================

document.addEventListener(
    "click",
    function (event) {
        const target =
            event.target;

        if (
            !target ||
            typeof target.closest !== "function"
        ) {
            return;
        }

        const copyTarget =
            target.closest(
                "#patchkiteCopyReport, .patchkite-copy-report"
            );

        if (copyTarget) {
            hapticLight();
        }
    }
);


// ============================================================
// VIEW REPORT HAPTIC
// ============================================================

document.addEventListener(
    "click",
    function (event) {
        const target =
            event.target;

        if (
            !target ||
            typeof target.closest !== "function"
        ) {
            return;
        }

        const reportTarget =
            target.closest(
                "#patchkiteViewReport, .patchkite-view-report"
            );

        if (reportTarget) {
            hapticLight();
        }
    }
);


// ============================================================
// NAVIGATION FEEDBACK FOR SHREY ANYWHERE
// ============================================================

document.querySelectorAll(
    "a, button"
).forEach(
    function (element) {
        const text =
            (element.textContent || "")
                .trim()
                .toLowerCase();

        if (text === "shrey") {
            element.addEventListener(
                "touchend",
                function () {
                    hapticShrey();
                },
                {
                    passive: true
                }
            );
        }
    }
);


// ============================================================
// RESUME SAVED SCAN
// ============================================================

async function resumeSavedScan() {
    const jobId =
        localStorage.getItem(
            STORAGE_JOB
        );

    const savedUrl =
        localStorage.getItem(
            STORAGE_URL
        );


    // No active scan:
    // do not restore an old URL.
    if (!jobId) {
        stopPolling();

        if (websiteUrl) {
            websiteUrl.value = "";
            websiteUrl.dataset.scanCompleted =
                "false";
        }

        if (scanButton) {
            scanButton.textContent =
                "SCAN WEBSITE";

            scanButton.disabled =
                false;
        }

        localStorage.removeItem(
            STORAGE_URL
        );

        return;
    }


    if (savedUrl && websiteUrl) {
        websiteUrl.value =
            savedUrl;
    }


    if (websiteUrl) {
        websiteUrl.dataset.scanCompleted =
            "false";
    }


    if (scanButton) {
        scanButton.textContent =
            "SCANNING...";

        scanButton.disabled =
            true;
    }


    hideReport();

    showScanningStatus(
        "Restoring your scan progress..."
    );


    startPolling(
        jobId,
        savedUrl ||
        (websiteUrl
            ? websiteUrl.value.trim()
            : "")
    );
}


// ============================================================
// INITIALIZE
// ============================================================

if (
    document.readyState === "loading"
) {
    document.addEventListener(
        "DOMContentLoaded",
        function () {
            resumeSavedScan();
        },
        {
            once: true
        }
    );
} else {
    resumeSavedScan();
}