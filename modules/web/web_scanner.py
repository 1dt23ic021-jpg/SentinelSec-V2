import requests


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

    if not url.startswith(("http://", "https://")):
        url = "https://" + url

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