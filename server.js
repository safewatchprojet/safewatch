require("dotenv").config();

const express = require("express");
const cors = require("cors");
const dns = require("dns").promises;

const app = express();

app.use(cors());
app.use(express.json());

const API_KEY = process.env.SAFE_BROWSING_API_KEY;

/* =========================================
   URL PATTERN ANALYSIS
========================================= */

function analyzeURL(input) {
    let score = 0;
    let reasons = [];
    let parsedURL;

    try {
        parsedURL = new URL(input);
    } catch {
        return {
            score: 100,
            risk: "HIGH RISK",
            reasons: ["Invalid or malformed URL"]
        };
    }

    const hostname = parsedURL.hostname.toLowerCase();
    const lowerInput = input.toLowerCase();

    /* HTTPS */

    if (parsedURL.protocol !== "https:") {
        score += 15;
        reasons.push("Website is not using HTTPS");
    }

    /* IP ADDRESS */

    const ipPattern = /^\d{1,3}(\.\d{1,3}){3}$/;

    if (ipPattern.test(hostname)) {
        score += 30;
        reasons.push(
            "Website uses an IP address instead of a normal domain"
        );
    }

    /* HIGH RISK WORDS */

    const highRiskWords = [
        "malware",
        "phishing",
        "credential-steal",
        "password-steal",
        "fake-login",
        "virus"
    ];

    highRiskWords.forEach(function (word) {
        if (lowerInput.includes(word)) {
            score += 70;

            reasons.push(
                "High-risk " + word + " pattern detected"
            );
        }
    });

    /* SCAM WORDS */

    const scamWords = [
        "scam",
        "free-money",
        "prize",
        "winner",
        "giveaway"
    ];

    scamWords.forEach(function (word) {
        if (lowerInput.includes(word)) {
            score += 30;

            reasons.push(
                "Suspicious " + word + " pattern detected"
            );
        }
    });

    /* DOWNLOAD WORDS */

    const downloadWords = [
        "crack",
        "cracked",
        "keygen",
        "serial-key",
        "mod-apk",
        "free-download",
        "download-now"
    ];

    downloadWords.forEach(function (word) {
        if (lowerInput.includes(word)) {
            score += 25;

            reasons.push(
                "Suspicious download-related pattern detected"
            );
        }
    });

    /* LOGIN WORDS */

    const loginWords = [
        "login",
        "signin",
        "verify-account",
        "account-verification",
        "secure-login"
    ];

    loginWords.forEach(function (word) {
        if (lowerInput.includes(word)) {
            score += 10;

            reasons.push(
                "Login or account-verification pattern detected"
            );
        }
    });

    /* COMPLEX DOMAIN */

    const parts = hostname.split(".");

    if (parts.length >= 5) {
        score += 15;

        reasons.push(
            "Unusually complex domain structure detected"
        );
    }

    /* LONG URL */

    if (input.length > 180) {
        score += 15;

        reasons.push(
            "Unusually long URL detected"
        );
    }

    /* SPECIAL CHARACTERS */

    const specialCharacters =
        (input.match(/[!@#$%^&*]/g) || []).length;

    if (specialCharacters >= 4) {
        score += 15;

        reasons.push(
            "Unusual number of special characters detected"
        );
    }

    /* @ SYMBOL */

    if (input.includes("@")) {
        score += 25;

        reasons.push(
            "URL contains @ symbol which can obscure the real destination"
        );
    }

    /* PUNYCODE */

    if (hostname.includes("xn--")) {
        score += 25;

        reasons.push(
            "Internationalized/Punycode domain detected"
        );
    }

    if (score > 100) {
        score = 100;
    }

    reasons = [...new Set(reasons)];

    let risk;

    if (score >= 60) {
        risk = "HIGH RISK";
    } else if (score >= 30) {
        risk = "SUSPICIOUS";
    } else {
        risk = "LOW RISK";
    }

    if (reasons.length === 0) {
        reasons.push(
            "No obvious suspicious URL pattern detected"
        );
    }

    return {
        score,
        risk,
        reasons
    };
}


/* =========================================
   DOMAIN / DNS INFORMATION
========================================= */

async function getDomainInformation(url) {
    let parsedURL;

    try {
        parsedURL = new URL(url);
    } catch {
        return {
            status: "INVALID",
            hostname: null,
            protocol: null,
            port: null,
            pathname: null,
            ipAddresses: {
                ipv4: [],
                ipv6: []
            },
            dns: {
                nameservers: [],
                mailServers: [],
                txtRecords: []
            }
        };
    }

    const hostname = parsedURL.hostname;

    let ipv4 = [];
    let ipv6 = [];
    let mx = [];
    let ns = [];
    let txt = [];

    /* IPv4 */

    try {
        ipv4 = await dns.resolve4(hostname);
    } catch {
        ipv4 = [];
    }

    /* IPv6 */

    try {
        ipv6 = await dns.resolve6(hostname);
    } catch {
        ipv6 = [];
    }

    /* MX */

    try {
        mx = await dns.resolveMx(hostname);
    } catch {
        mx = [];
    }

    /* NS */

    try {
        ns = await dns.resolveNs(hostname);
    } catch {
        ns = [];
    }

    /* TXT */

    try {
        txt = await dns.resolveTxt(hostname);
    } catch {
        txt = [];
    }

    return {
        status: "SUCCESS",

        hostname: hostname,

        protocol: parsedURL.protocol,

        port: parsedURL.port || "Default",

        pathname: parsedURL.pathname,

        search: parsedURL.search || "",

        hash: parsedURL.hash || "",

        ipAddresses: {
            ipv4: ipv4,
            ipv6: ipv6
        },

        dns: {
            nameservers: ns,
            mailServers: mx,
            txtRecords: txt
        }
    };
}


/* =========================================
   GOOGLE SAFE BROWSING
========================================= */

async function checkSafeBrowsing(url) {
    if (
        !API_KEY ||
        API_KEY === "PASTE_YOUR_KEY_HERE"
    ) {
        return {
            status: "NOT_CONFIGURED",
            message:
                "Safe Browsing API key is not configured"
        };
    }

    try {
        console.log(
            "Checking Google Safe Browsing..."
        );

        const apiURL =
            "https://safebrowsing.googleapis.com/v4/threatMatches:find?key=" +
            encodeURIComponent(API_KEY);

        const response = await fetch(
            apiURL,
            {
                method: "POST",

                headers: {
                    "Content-Type": "application/json"
                },

                body: JSON.stringify({
                    client: {
                        clientId: "safewatch",
                        clientVersion: "2.0"
                    },

                    threatInfo: {
                        threatTypes: [
                            "MALWARE",
                            "SOCIAL_ENGINEERING",
                            "UNWANTED_SOFTWARE",
                            "POTENTIALLY_HARMFUL_APPLICATION"
                        ],

                        platformTypes: [
                            "ANY_PLATFORM"
                        ],

                        threatEntryTypes: [
                            "URL"
                        ],

                        threatEntries: [
                            {
                                url: url
                            }
                        ]
                    }
                })
            }
        );

        console.log(
            "Safe Browsing HTTP:",
            response.status
        );

        const contentType =
            response.headers.get(
                "content-type"
            ) || "";

        console.log(
            "Safe Browsing Content-Type:",
            contentType
        );

        if (!response.ok) {
            const errorText =
                await response.text();

            console.error(
                "Safe Browsing API error:",
                errorText
            );

            return {
                status: "API_ERROR",
                httpStatus: response.status,
                message:
                    "Threat reputation service returned an error"
            };
        }

        /*
           Google Safe Browsing normally returns JSON.
        */

        if (
            contentType
                .toLowerCase()
                .includes("application/json")
        ) {
            const data =
                await response.json();

            if (
                data.matches &&
                data.matches.length > 0
            ) {
                return {
                    status: "THREAT_FOUND",

                    matches:
                        data.matches.map(
                            function (match) {
                                return {
                                    threatType:
                                        match.threatType,

                                    platformType:
                                        match.platformType,

                                    threatEntryType:
                                        match.threatEntryType
                                };
                            }
                        )
                };
            }

            return {
                status: "NO_THREAT_FOUND",
                matches: []
            };
        }

        return {
            status: "API_ERROR",

            message:
                "Safe Browsing returned an unsupported response format",

            contentType: contentType
        };

    } catch (error) {
        console.error(
            "Safe Browsing request failed:",
            error.message
        );

        return {
            status: "API_ERROR",

            message:
                "Threat reputation check failed"
        };
    }
}


/* =========================================
   DETAILED THREAT ANALYSIS
========================================= */

function createThreatAnalysis(
    localResult,
    reputation,
    domainInfo
) {
    const checks = [];

    checks.push({
        name: "URL pattern analysis",
        status:
            localResult.score >= 60
                ? "HIGH RISK"
                : localResult.score >= 30
                    ? "SUSPICIOUS"
                    : "PASS",
        details:
            localResult.reasons
    });

    checks.push({
        name: "HTTPS security",
        status:
            domainInfo.protocol === "https:"
                ? "PASS"
                : "WARNING",
        details:
            domainInfo.protocol === "https:"
                ? "HTTPS is enabled"
                : "Website is not using HTTPS"
    });

    const hasIPv4 =
        domainInfo.ipAddresses &&
        domainInfo.ipAddresses.ipv4 &&
        domainInfo.ipAddresses.ipv4.length > 0;

    checks.push({
        name: "IP address resolution",
        status: hasIPv4
            ? "INFO"
            : "UNKNOWN",
        details: hasIPv4
            ? "IPv4 address resolved"
            : "No IPv4 address resolved"
    });

    checks.push({
        name: "Google Safe Browsing",
        status:
            reputation.status ===
            "THREAT_FOUND"
                ? "HIGH RISK"
                : reputation.status ===
                  "NO_THREAT_FOUND"
                    ? "PASS"
                    : "UNKNOWN",
        details:
            reputation.status
    });

    let threatLevel = "LOW";

    if (
        reputation.status ===
        "THREAT_FOUND"
    ) {
        threatLevel = "CRITICAL";
    } else if (
        localResult.score >= 60
    ) {
        threatLevel = "HIGH";
    } else if (
        localResult.score >= 30
    ) {
        threatLevel = "MEDIUM";
    }

    return {
        threatLevel: threatLevel,

        checks: checks,

        totalChecks: checks.length,

        recommendations: [
            "Verify the domain before entering sensitive information",
            "Do not download unknown files",
            "Do not enter passwords on suspicious pages",
            "Keep browser security warnings enabled"
        ]
    };
}


/* =========================================
   SCAN ENDPOINT
========================================= */

app.post(
    "/scan",
    async function (req, res) {

        const input =
            (req.body.url || "")
                .trim();

        if (!input) {
            return res.status(400).json({
                error: "URL is required"
            });
        }

        console.log(
            "Scanning:",
            input
        );

        /* LOCAL ANALYSIS */

        const localResult =
            analyzeURL(input);

        /* DOMAIN INFORMATION */

        const domainInfo =
            await getDomainInformation(
                input
            );

        /* GOOGLE SAFE BROWSING */

        const reputation =
            await checkSafeBrowsing(
                input
            );

        /* THREAT FOUND */

        if (
            reputation.status ===
            "THREAT_FOUND"
        ) {
            localResult.score = 100;

            localResult.risk =
                "HIGH RISK";

            localResult.reasons.push(
                "Google Safe Browsing detected a known threat"
            );

            reputation.matches.forEach(
                function (match) {
                    localResult.reasons.push(
                        "Threat type: " +
                        match.threatType
                    );
                }
            );
        }

        localResult.reasons =
            [
                ...new Set(
                    localResult.reasons
                )
            ];

        /* DETAILED THREAT REPORT */

        const threatAnalysis =
            createThreatAnalysis(
                localResult,
                reputation,
                domainInfo
            );

        /* FINAL REPORT */

        const report = {
            scannedURL: input,

            scanTime:
                new Date().toISOString(),

            risk:
                localResult.risk,

            score:
                localResult.score,

            domainInformation:
                domainInfo,

            urlAnalysis: {
                score:
                    localResult.score,

                risk:
                    localResult.risk,

                reasons:
                    localResult.reasons
            },

            googleSafeBrowsing:
                reputation,

            detailedThreatAnalysis:
                threatAnalysis,

            securitySummary: {
                https:
                    domainInfo.protocol ===
                    "https:",

                ipAddressDetected:
                    domainInfo.ipAddresses &&
                    domainInfo.ipAddresses.ipv4 &&
                    domainInfo.ipAddresses.ipv4.length > 0,

                knownThreat:
                    reputation.status ===
                    "THREAT_FOUND",

                overallRisk:
                    localResult.risk
            }
        };

        res.json(report);
    }
);


/* =========================================
   DOMAIN REPORT ENDPOINT
========================================= */

app.post(
    "/domain-report",
    async function (req, res) {

        const input =
            (req.body.url || "")
                .trim();

        if (!input) {
            return res.status(400).json({
                error: "URL is required"
            });
        }

        const domainInfo =
            await getDomainInformation(
                input
            );

        res.json({
            scannedURL: input,

            scanTime:
                new Date().toISOString(),

            domainInformation:
                domainInfo
        });
    }
);


/* =========================================
   HOME
========================================= */

app.get(
    "/",
    function (req, res) {

        res.json({
            message:
                "SafeWatch Backend is running!",

            version:
                "2.1",

            apiStatus:
                API_KEY &&
                API_KEY !==
                "PASTE_YOUR_KEY_HERE"
                    ? "CONFIGURED"
                    : "NOT CONFIGURED",

            endpoints: [
                "POST /scan",
                "POST /domain-report"
            ]
        });
    }
);


/* =========================================
   SERVER
========================================= */

const PORT = 3000;

app.listen(
    PORT,
    function () {

        console.log(
            "SafeWatch v2.1 running at http://localhost:" +
            PORT
        );

    }
);