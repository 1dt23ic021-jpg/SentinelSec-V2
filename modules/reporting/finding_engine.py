"""
SentinelSec V2 - Findings and Risk Engine

Converts network and web scan observations into structured,
evidence-based security findings.

These findings identify configurations that deserve review.
They do not automatically prove a vulnerability is exploitable.
"""

from collections import Counter


SEVERITY_LEVELS = (
    "Critical",
    "High",
    "Medium",
    "Low",
    "Informational",
)


# Rules for recognizable network services.
NETWORK_RULES = {
    23: {
        "title": "Telnet service reachable",
        "severity": "High",
        "description": (
            "Traditional Telnet does not encrypt administrative "
            "traffic. Confirm whether this service is required."
        ),
        "recommendation": (
            "Prefer SSH for remote administration and restrict "
            "access to trusted management networks."
        ),
    },
    21: {
        "title": "FTP service reachable",
        "severity": "Medium",
        "description": (
            "Traditional FTP does not encrypt credentials or "
            "file contents. Reachability alone does not prove "
            "that sensitive data is exposed."
        ),
        "recommendation": (
            "Use SFTP or properly configured FTPS when encrypted "
            "file transfer is required, and restrict access."
        ),
    },
    3306: {
        "title": "MySQL service reachable",
        "severity": "Medium",
        "description": (
            "A MySQL service responded on the scanned port. "
            "This does not prove unauthorized access."
        ),
        "recommendation": (
            "Confirm whether remote database access is required "
            "and restrict access to approved hosts."
        ),
    },
    5432: {
        "title": "PostgreSQL service reachable",
        "severity": "Medium",
        "description": (
            "A PostgreSQL service responded on the scanned port. "
            "This does not prove unauthorized access."
        ),
        "recommendation": (
            "Restrict database connections to approved application "
            "hosts and trusted management networks."
        ),
    },
    6379: {
        "title": "Redis service reachable",
        "severity": "Medium",
        "description": (
            "A Redis service responded on the scanned port. "
            "The scan does not determine whether authentication "
            "is enabled or data is accessible."
        ),
        "recommendation": (
            "Restrict Redis to trusted networks and verify "
            "authentication and other deployment security controls."
        ),
    },
    27017: {
        "title": "MongoDB service reachable",
        "severity": "Medium",
        "description": (
            "A MongoDB service responded on the scanned port. "
            "The scan does not establish whether data is exposed."
        ),
        "recommendation": (
            "Restrict database access to approved hosts and "
            "verify authentication and network controls."
        ),
    },
}


# Rules for web response security headers.
WEB_HEADER_RULES = {
    "Content-Security-Policy": {
        "severity": "Medium",
        "title": "Content-Security-Policy header missing",
        "description": (
            "The observed response did not include a "
            "Content-Security-Policy header."
        ),
        "recommendation": (
            "Define and test a Content Security Policy appropriate "
            "for the application's scripts, styles, frames, "
            "and other required resources."
        ),
    },
    "Strict-Transport-Security": {
        "severity": "Medium",
        "title": "Strict-Transport-Security header missing",
        "description": (
            "The observed HTTPS response did not include "
            "a Strict-Transport-Security header."
        ),
        "recommendation": (
            "If the site should use HTTPS exclusively, configure "
            "HSTS after verifying HTTPS works correctly."
        ),
    },
    "X-Content-Type-Options": {
        "severity": "Low",
        "title": "X-Content-Type-Options header missing",
        "description": (
            "The response did not include X-Content-Type-Options."
        ),
        "recommendation": (
            "Consider setting X-Content-Type-Options: nosniff."
        ),
    },
    "X-Frame-Options": {
        "severity": "Low",
        "title": "X-Frame-Options header missing",
        "description": (
            "The response did not include X-Frame-Options."
        ),
        "recommendation": (
            "Review framing requirements and configure "
            "X-Frame-Options or a suitable CSP frame-ancestors rule."
        ),
    },
    "Referrer-Policy": {
        "severity": "Low",
        "title": "Referrer-Policy header missing",
        "description": (
            "The response did not include Referrer-Policy."
        ),
        "recommendation": (
            "Set a Referrer-Policy suitable for the application's "
            "privacy requirements."
        ),
    },
    "Permissions-Policy": {
        "severity": "Informational",
        "title": "Permissions-Policy header missing",
        "description": (
            "The response did not include Permissions-Policy."
        ),
        "recommendation": (
            "Review browser features used by the application and "
            "restrict unnecessary features where appropriate."
        ),
    },
}


def _make_finding(
    finding_id,
    category,
    title,
    severity,
    description,
    evidence,
    recommendation,
    source,
    asset,
):
    """Create one finding using a consistent data structure."""

    return {
        "finding_id": finding_id,
        "category": category,
        "title": title,
        "severity": severity,
        "description": description,
        "evidence": evidence,
        "recommendation": recommendation,
        "source": source,
        "asset": asset,
        "assessment_note": (
            "Rule-based observation. Validate the finding in context "
            "before treating it as a confirmed vulnerability."
        ),
    }


def analyze_network_findings(scan_results=None):
    """
    Generate findings from recognized open TCP ports.

    Expected input:
        [
            {
                "port": 23,
                "status": "open",
                "service": "Telnet",
                "banner": ""
            }
        ]
    """

    findings = []

    for result in scan_results or []:
        if not isinstance(result, dict):
            continue

        status = str(result.get("status", "open")).lower()

        if status != "open":
            continue

        try:
            port = int(result.get("port"))
        except (TypeError, ValueError):
            continue

        rule = NETWORK_RULES.get(port)

        if rule is None:
            continue

        service = result.get("service") or "Unknown service"

        evidence = (
            f"TCP port {port} is open; "
            f"detected service: {service}."
        )

        banner = result.get("banner")

        if banner:
            evidence += f" Banner: {str(banner).strip()[:240]}"

        findings.append(
            _make_finding(
                finding_id=f"NET-{len(findings) + 1:03d}",
                category="Network Service Configuration",
                title=rule["title"],
                severity=rule["severity"],
                description=rule["description"],
                evidence=evidence,
                recommendation=rule["recommendation"],
                source="port_scan",
                asset=f"TCP/{port}",
            )
        )

    return findings


def analyze_web_findings(web_result=None):
    """
    Generate findings from the current web scanner's output.
    """

    if not isinstance(web_result, dict):
        return []

    if web_result.get("error"):
        return []

    findings = []

    url = (
        web_result.get("final_url")
        or web_result.get("requested_url")
        or web_result.get("url")
        or "Unknown URL"
    )

    https = web_result.get("https")

    if https is None:
        https = str(url).lower().startswith("https://")

    def add_web_finding(
        title,
        severity,
        description,
        evidence,
        recommendation,
        asset=None,
    ):
        """Add a web finding with a sequential ID."""

        findings.append(
            _make_finding(
                finding_id=f"WEB-{len(findings) + 1:03d}",
                category="Web Security Configuration",
                title=title,
                severity=severity,
                description=description,
                evidence=evidence,
                recommendation=recommendation,
                source="web_scan",
                asset=asset or url,
            )
        )

    # Check whether the final response used HTTPS.
    if not https:
        add_web_finding(
            title="HTTP used for final response",
            severity="Medium",
            description=(
                "The final response URL uses HTTP, so transport "
                "encryption was not observed for that response."
            ),
            evidence=f"Final response URL: {url}",
            recommendation=(
                "Serve the application over HTTPS and redirect "
                "HTTP requests to HTTPS where appropriate. Verify "
                "that sensitive pages are protected."
            ),
        )

    # Read the header values returned by web_scanner.py.
    header_values = web_result.get("security_headers") or {}

    for header, rule in WEB_HEADER_RULES.items():

        # HSTS is relevant to HTTPS responses.
        if header == "Strict-Transport-Security" and not https:
            continue

        if not header_values.get(header):
            add_web_finding(
                title=rule["title"],
                severity=rule["severity"],
                description=rule["description"],
                evidence=(
                    f"Response from {url} did not contain "
                    f"the {header} header."
                ),
                recommendation=rule["recommendation"],
            )

    # Review cookie attributes reported by the existing scanner.
    for cookie in web_result.get("cookies") or []:

        if not isinstance(cookie, dict):
            continue

        cookie_name = str(cookie.get("name") or "unnamed cookie")

        if https and not cookie.get("secure", False):
            add_web_finding(
                title="Cookie missing Secure attribute",
                severity="Medium",
                description=(
                    "A cookie observed on an HTTPS response was "
                    "not marked Secure. Review whether it holds "
                    "session or other sensitive information."
                ),
                evidence=(
                    f"Cookie '{cookie_name}' has "
                    f"Secure={cookie.get('secure', False)}."
                ),
                recommendation=(
                    "Set the Secure attribute for cookies that "
                    "should only be sent over HTTPS."
                ),
            )

        if not cookie.get("httponly", False):
            add_web_finding(
                title="Cookie missing HttpOnly attribute",
                severity="Low",
                description=(
                    "A cookie was observed without the HttpOnly "
                    "attribute. The impact depends on its purpose."
                ),
                evidence=(
                    f"Cookie '{cookie_name}' has "
                    f"HttpOnly={cookie.get('httponly', False)}."
                ),
                recommendation=(
                    "Set HttpOnly for session cookies and other "
                    "cookies that do not need JavaScript access."
                ),
            )

        same_site = cookie.get("samesite")

        if not same_site:
            add_web_finding(
                title="Cookie SameSite attribute not observed",
                severity="Low",
                description=(
                    "The scanner did not observe a SameSite "
                    "attribute in the cookie metadata."
                ),
                evidence=(
                    f"Cookie '{cookie_name}' has "
                    f"SameSite={same_site!r}."
                ),
                recommendation=(
                    "Choose an appropriate SameSite value "
                    "(Strict, Lax, or None) for the cookie's use."
                ),
            )

    return findings


def generate_findings(scan_results=None, web_result=None):
    """Combine network and web findings."""

    network_findings = analyze_network_findings(scan_results)
    web_findings = analyze_web_findings(web_result)

    return network_findings + web_findings


def summarize_findings(findings=None):
    """Count findings by severity."""

    counts = Counter(
        finding.get("severity")
        for finding in (findings or [])
        if isinstance(finding, dict)
    )

    summary = {
        severity: counts.get(severity, 0)
        for severity in SEVERITY_LEVELS
    }

    summary["Total"] = sum(summary.values())

    return summary