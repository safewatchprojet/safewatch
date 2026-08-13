require("dotenv").config();

const express = require("express");
const cors = require("cors");
const dns = require("dns").promises;

const app = express();

app.use(cors());
app.use(express.json());

const API_KEY = process.env.SAFE_BROWSING_API_KEY;


/* =========================================
   SAFEWATCH v4.2
   THREAT-FOCUSED URL PROTECTION
========================================= */


/* =========================================
   URL ANALYSIS
========================================= */

function analyzeURL(input) {

    let score = 0;
    let reasons = [];
    let parsedURL;


    /* =====================================
       URL VALIDATION
    ===================================== */

    try {

        parsedURL = new URL(input);

    } catch {

        return {
            score: 100,
            risk: "HIGH RISK",
            reasons: [
                "Invalid or malformed URL"
            ]
        };
    }


    const hostname =
        parsedURL.hostname.toLowerCase();

    const lowerInput =
        input.toLowerCase();


    /* =====================================
       PROTOCOL
    ===================================== */

    if (
        parsedURL.protocol !== "https:" &&
        parsedURL.protocol !== "http:"
    ) {

        score += 50;

        reasons.push(
            "Unsupported URL protocol detected"
        );
    }


    /* =====================================
       IP ADDRESS
    ===================================== */

    const ipPattern =
        /^\d{1,3}(\.\d{1,3}){3}$/;


    if (
        ipPattern.test(hostname)
    ) {

        score += 30;

        reasons.push(
            "Website uses an IP address instead of a normal domain"
        );
    }


    /* =====================================
       HIGH-RISK PATTERNS
    ===================================== */

    const highRiskWords = [

        "malware",
        "phishing",
        "credential-steal",
        "password-steal",
        "fake-login",
        "virus"
    ];


    highRiskWords.forEach(
        function(word) {

            if (
                lowerInput.includes(word)
            ) {

                score += 70;

                reasons.push(
                    "High-risk " +
                    word +
                    " pattern detected"
                );
            }
        }
    );


    /* =====================================
       SCAM PATTERNS
    ===================================== */

    const scamWords = [

        "scam",
        "free-money",
        "prize",
        "winner",
        "giveaway"
    ];


    scamWords.forEach(
        function(word) {

            if (
                lowerInput.includes(word)
            ) {

                score += 30;

                reasons.push(
                    "Suspicious " +
                    word +
                    " pattern detected"
                );
            }
        }
    );


    /* =====================================
       SUSPICIOUS DOWNLOAD PATTERNS
    ===================================== */

    const downloadWords = [

        "crack",
        "cracked",
        "keygen",
        "serial-key",
        "mod-apk",
        "free-download",
        "download-now"
    ];


    downloadWords.forEach(
        function(word) {

            if (
                lowerInput.includes(word)
            ) {

                score += 25;

                reasons.push(
                    "Suspicious download-related pattern detected"
                );
            }
        }
    );


    /* =====================================
       UNOFFICIAL STREAMING PATTERNS
    ===================================== */

    const suspiciousContentWords = [

        "movie-download",
        "movies-download",
        "download-movie",
        "free-movies",
        "watch-free",
        "camrip",
        "dvdrip",
        "webrip",
        "hdrip",
        "bluray",
        "web-dl"
    ];


    let suspiciousContentCount = 0;


    suspiciousContentWords.forEach(
        function(word) {

            if (
                lowerInput.includes(word)
            ) {

                suspiciousContentCount++;
            }
        }
    );


    if (
        suspiciousContentCount >= 2
    ) {

        score += 40;

        reasons.push(
            "Multiple unofficial streaming/download-related URL patterns detected"
        );

    } else if (
        suspiciousContentCount === 1
    ) {

        score += 20;

        reasons.push(
            "Unofficial streaming/download-related URL pattern detected"
        );
    }


    /* =====================================
       ACCOUNT VERIFICATION PATTERNS
    ===================================== */

    const verificationWords = [

        "verify-account",
        "account-verification",
        "secure-login",
        "verify-password",
        "confirm-account"
    ];


    verificationWords.forEach(
        function(word) {

            if (
                lowerInput.includes(word)
            ) {

                score += 20;

                reasons.push(
                    "Account verification pattern detected"
                );
            }
        }
    );


    /* =====================================
       LOGIN COMBINATION
    ===================================== */

    /*
       "login" or "signin" alone is normal.

       Only suspicious when combined with
       another account/password indicator.
    */

    const hasLoginWord =
        lowerInput.includes("login") ||
        lowerInput.includes("signin");


    const hasAccountIndicator =
        lowerInput.includes("password") ||
        lowerInput.includes("verify") ||
        lowerInput.includes("secure") ||
        lowerInput.includes("account");


    if (
        hasLoginWord &&
        hasAccountIndicator
    ) {

        score += 15;

        reasons.push(
            "Login and account-verification pattern combination detected"
        );
    }


    /* =====================================
       COMPLEX DOMAIN
    ===================================== */

    const parts =
        hostname.split(".");


    if (
        parts.length >= 6
    ) {

        score += 10;

        reasons.push(
            "Unusually complex domain structure detected"
        );
    }


    /* =====================================
       LONG URL
    ===================================== */

    /*
       INTENTIONALLY NOT SCORED.

       Long URLs are normal on:

       - Google
       - Amazon
       - Flipkart
       - YouTube
       - ChatGPT
       - Gemini
       - Shopping sites
       - Search engines
    */


    /* =====================================
       SPECIAL CHARACTERS
    ===================================== */

    /*
       INTENTIONALLY NOT SCORED.

       Normal URL characters such as:

       ?
       &
       =
       %
       -
       _
       /
       :

       are not evidence of a threat.
    */


    /* =====================================
       @ SYMBOL
    ===================================== */

    if (
        input.includes("@")
    ) {

        score += 25;

        reasons.push(
            "URL contains @ symbol which can obscure the real destination"
        );
    }


    /* =====================================
       PUNYCODE
    ===================================== */

    if (
        hostname.includes("xn--")
    ) {

        score += 25;

        reasons.push(
            "Internationalized/Punycode domain detected"
        );
    }


    /* =====================================
       MULTIPLE INDICATORS
    ===================================== */

    const uniqueIndicators =
        new Set(reasons).size;


    /*
       Small additional score only when
       several independent suspicious signals
       already exist.
    */

    if (
        uniqueIndicators >= 3 &&
        score >= 30
    ) {

        score += 10;
    }


    /* =====================================
       LIMIT SCORE
    ===================================== */

    if (
        score > 100
    ) {

        score = 100;
    }


    /* =====================================
       REMOVE DUPLICATES
    ===================================== */

    reasons =
        [...new Set(reasons)];


    /* =====================================
       RISK LEVEL
    ===================================== */

    let risk;


    if (
        score >= 60
    ) {

        risk = "HIGH RISK";

    } else if (
        score >= 40
    ) {

        risk = "SUSPICIOUS";

    } else {

        risk = "LOW RISK";
    }


    /* =====================================
       DEFAULT REASON
    ===================================== */

    if (
        reasons.length === 0
    ) {

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

        parsedURL =
            new URL(url);

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


    const hostname =
        parsedURL.hostname;


    let ipv4 = [];
    let ipv6 = [];
    let mx = [];
    let ns = [];
    let txt = [];


    try {

        ipv4 =
            await dns.resolve4(
                hostname
            );

    } catch {}


    try {

        ipv6 =
            await dns.resolve6(
                hostname
            );

    } catch {}


    try {

        mx =
            await dns.resolveMx(
                hostname
            );

    } catch {}


    try {

        ns =
            await dns.resolveNs(
                hostname
            );

    } catch {}


    try {

        txt =
            await dns.resolveTxt(
                hostname
            );

    } catch {}


    return {

        status: "SUCCESS",

        hostname,

        protocol:
            parsedURL.protocol,

        port:
            parsedURL.port ||
            "Default",

        pathname:
            parsedURL.pathname,

        search:
            parsedURL.search ||
            "",

        hash:
            parsedURL.hash ||
            "",

        ipAddresses: {

            ipv4,

            ipv6
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
        API_KEY ===
        "PASTE_YOUR_KEY_HERE"
    ) {

        return {

            status:
                "NOT_CONFIGURED",

            message:
                "Safe Browsing API key is not configured"
        };
    }


    try {

        const apiURL =
            "https://safebrowsing.googleapis.com/v4/threatMatches:find?key=" +
            encodeURIComponent(
                API_KEY
            );


        const response =
            await fetch(
                apiURL,
                {

                    method: "POST",

                    headers: {

                        "Content-Type":
                            "application/json"
                    },

                    body:
                        JSON.stringify({

                            client: {

                                clientId:
                                    "safewatch",

                                clientVersion:
                                    "4.2"
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
                                        url
                                    }
                                ]
                            }
                        })
                }
            );


        if (
            !response.ok
        ) {

            return {

                status:
                    "API_ERROR",

                httpStatus:
                    response.status
            };
        }


        const contentType =
            response.headers.get(
                "content-type"
            ) || "";


        if (
            contentType
                .toLowerCase()
                .includes(
                    "application/json"
                )
        ) {

            const data =
                await response.json();


            if (
                data.matches &&
                data.matches.length > 0
            ) {

                return {

                    status:
                        "THREAT_FOUND",

                    matches:
                        data.matches.map(
                            function(match) {

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

                status:
                    "NO_THREAT_FOUND",

                matches: []
            };
        }


        return {

            status:
                "API_ERROR"
        };


    } catch (error) {

        return {

            status:
                "API_ERROR",

            message:
                "Threat reputation check failed"
        };
    }
}


/* =========================================
   PROTECTION ENGINE
========================================= */

function createProtectionDecision(
    localResult,
    reputation
) {

    let action =
        "ALLOW";

    let protectionLevel =
        "SAFE";


    /* =====================================
       KNOWN GOOGLE THREAT
    ===================================== */

    if (
        reputation.status ===
        "THREAT_FOUND"
    ) {

        action =
            "BLOCK";

        protectionLevel =
            "CRITICAL";
    }


    /* =====================================
       HIGH RISK
    ===================================== */

    else if (
        localResult.score >= 60
    ) {

        action =
            "BLOCK";

        protectionLevel =
            "HIGH";
    }


    /* =====================================
       SUSPICIOUS
    ===================================== */

    else if (
        localResult.score >= 40
    ) {

        action =
            "WARN";

        protectionLevel =
            "MEDIUM";
    }


    /* =====================================
       SAFE
    ===================================== */

    else {

        action =
            "ALLOW";

        protectionLevel =
            "SAFE";
    }


    return {

        action,

        protectionLevel,

        blocked:
            action === "BLOCK",

        warning:
            action === "WARN",

        safe:
            action === "ALLOW"
    };
}


/* =========================================
   SCAN ENDPOINT
========================================= */

app.post(
    "/scan",
    async function(req, res) {

        const input =
            (req.body.url || "")
                .trim();


        if (
            !input
        ) {

            return res
                .status(400)
                .json({

                    error:
                        "URL is required"
                });
        }


        const localResult =
            analyzeURL(input);


        const domainInfo =
            await getDomainInformation(
                input
            );


        const reputation =
            await checkSafeBrowsing(
                input
            );


        /* =================================
           GOOGLE THREAT OVERRIDE
        ================================= */

        if (
            reputation.status ===
            "THREAT_FOUND"
        ) {

            localResult.score =
                100;


            localResult.risk =
                "HIGH RISK";


            localResult.reasons.push(
                "Google Safe Browsing detected a known threat"
            );


            reputation.matches.forEach(
                function(match) {

                    localResult.reasons.push(
                        "Threat type: " +
                        match.threatType
                    );
                }
            );
        }


        localResult.reasons =
            [...new Set(
                localResult.reasons
            )];


        const protection =
            createProtectionDecision(
                localResult,
                reputation
            );


        /* =================================
           FINAL REPORT
        ================================= */

        const report = {

            version:
                "4.2",

            scannedURL:
                input,

            scanTime:
                new Date()
                    .toISOString(),

            risk:
                localResult.risk,

            score:
                localResult.score,

            protection,

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

            securitySummary: {

                https:
                    domainInfo.protocol ===
                    "https:",

                ipAddressDetected:
                    /^\d{1,3}(\.\d{1,3}){3}$/
                        .test(
                            domainInfo.hostname ||
                            ""
                        ),

                knownThreat:
                    reputation.status ===
                    "THREAT_FOUND",

                overallRisk:
                    localResult.risk
            },

            securityRecommendations: [

                "Do not enter passwords on suspicious websites",

                "Do not enter OTP or banking information",

                "Do not download unknown files",

                "Verify the domain name before continuing",

                "Keep browser security protection enabled"
            ]
        };


        res.json(
            report
        );
    }
);


/* =========================================
   PROTECTION STATUS
========================================= */

app.get(
    "/protection-status",
    function(req, res) {

        res.json({

            product:
                "SafeWatch",

            version:
                "4.2",

            protection:
                "ACTIVE",

            description:
                "SafeWatch URL threat protection system",

            supportedActions: [

                "ALLOW",

                "WARN",

                "BLOCK"
            ]
        });
    }
);


/* =========================================
   DOMAIN REPORT
========================================= */

app.post(
    "/domain-report",
    async function(req, res) {

        const input =
            (req.body.url || "")
                .trim();


        if (
            !input
        ) {

            return res
                .status(400)
                .json({

                    error:
                        "URL is required"
                });
        }


        const domainInfo =
            await getDomainInformation(
                input
            );


        res.json({

            scannedURL:
                input,

            scanTime:
                new Date()
                    .toISOString(),

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
    function(req, res) {

        res.json({

            message:
                "SafeWatch Backend is running!",

            version:
                "4.2",

            protection:
                "ACTIVE",

            apiStatus:

                API_KEY &&
                API_KEY !==
                "PASTE_YOUR_KEY_HERE"

                    ? "CONFIGURED"

                    : "NOT CONFIGURED",

            endpoints: [

                "POST /scan",

                "POST /domain-report",

                "GET /protection-status"
            ]
        });
    }
);


/* =========================================
   SERVER
========================================= */

const PORT =
    process.env.PORT || 3000;


app.listen(
    PORT,
    function() {

        console.log(
            "SafeWatch v4.2 running at http://localhost:" +
            PORT
        );
    }
);