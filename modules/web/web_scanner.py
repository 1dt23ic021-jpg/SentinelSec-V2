import requests
from urllib.parse import urlsplit


SECURITY_HEADERS = {
    "Content-Security-Policy": (
        "Helps control which resources a browser is allowed to load."
    ),
    "Strict-Transport-Security": (
        "Forces browsers to use HTTPS for future requests."
    ),
    "X-Content-Type-Options": (
        "Helps prevent MIME type sniffing."
    ),
    "X-Frame-Options": (
        "Helps reduce clickjacking risk."
    ),
    "Referrer-Policy": (
        "Controls how much referrer information is sent."
    ),
    "Permissions-Policy": (
        "Controls access to browser features."
    ),
}


def scan_web_target(url, timeout=5):
    """
    Perform a passive web-security configuration assessment.
    """

    if not isinstance(url, str) or not url.strip():
        return {"url": url, "error": "A valid URL is required."}

    url = url.strip()

    # Preserve the existing behavior of adding HTTPS when no scheme is given.
    if "://" not in url:
        url = "https://" + url

    try:
        parsed_url = urlsplit(url)

        if parsed_url.scheme.lower() not in ("http", "https"):
            return {
                "url": url,
                "error": "Only HTTP and HTTPS URLs are supported."
            }

        if not parsed_url.hostname:
            return {
                "url": url,
                "error": "The URL must include a hostname."
            }

        # Validate the port if one was explicitly supplied.
        _ = parsed_url.port

        if parsed_url.username is not None or parsed_url.password is not None:
            return {
                "url": url,
                "error": "URLs containing embedded credentials are not allowed."
            }

        timeout = float(timeout)

        if not 0 < timeout <= 30:
            return {
                "url": url,
                "error": "Timeout must be greater than 0 and at most 30 seconds."
            }

    except (ValueError, TypeError, OverflowError):
        return {
            "url": url,
            "error": "Invalid URL or timeout value."
        }

    try:
        response = requests.get(
            url,
            timeout=timeout,
            allow_redirects=True
        )

    except requests.RequestException as error:
        return {
            "url": url,
            "error": str(error)
        }

    findings = []
    headers = response.headers

    for header, description in SECURITY_HEADERS.items():
        if header not in headers:
            findings.append({
                "type": "Missing Security Header",
                "header": header,
                "description": description
            })

    cookies = []

    for cookie in response.cookies:
        cookies.append({
            "name": cookie.name,
            "secure": cookie.secure,
            "httponly": "HttpOnly" in cookie._rest,
            "samesite": cookie._rest.get("SameSite")
        })

    if response.url.startswith("http://"):
        findings.append({
            "type": "HTTPS",
            "description": "Target is using HTTP instead of HTTPS."
        })

    server_header = headers.get("Server")

    return {
        "requested_url": url,
        "final_url": response.url,
        "status_code": response.status_code,
        "https": response.url.startswith("https://"),
        "server": server_header,
        "security_headers": {
            header: headers.get(header)
            for header in SECURITY_HEADERS
        },
        "cookies": cookies,
        "findings": findings
    }


def print_web_summary(result):
    """
    Display web-security scan results.
    """

    if "error" in result:
        print(f"\nWeb scan error: {result['error']}")
        return

    print("\nWeb Security Assessment")
    print("-" * 40)

    print(f"URL         : {result['final_url']}")
    print(f"Status      : {result['status_code']}")
    print(f"HTTPS       : {result['https']}")
    print(f"Server      : {result['server'] or 'Not disclosed'}")

    print("\nSecurity Headers:")

    for header, value in result["security_headers"].items():
        status = "Present" if value else "Missing"
        print(f"  {header}: {status}")

    print("\nCookies:")

    if result["cookies"]:
        for cookie in result["cookies"]:
            print(
                f"  {cookie['name']} | "
                f"Secure={cookie['secure']} | "
                f"HttpOnly={cookie['httponly']} | "
                f"SameSite={cookie['samesite']}"
            )
    else:
        print("  No cookies detected.")

    print("\nFindings:")

    if result["findings"]:
        for finding in result["findings"]:
            print(
                f"  - {finding['type']}: "
                f"{finding.get('header', finding.get('description'))}"
            )
    else:
        print("  No configuration findings detected.")