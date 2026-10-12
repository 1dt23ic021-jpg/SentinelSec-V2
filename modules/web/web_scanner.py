import ipaddress
import socket
from urllib.parse import urljoin, urlsplit

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


def _validate_public_url(url):
    """Reject malformed URLs and non-public destination addresses."""

    try:
        parsed = urlsplit(url)

        if parsed.scheme.lower() not in ("http", "https"):
            return False

        if not parsed.hostname:
            return False

        if parsed.username is not None or parsed.password is not None:
            return False

        port = parsed.port
        if port is not None and not 1 <= port <= 65535:
            return False

        hostname = parsed.hostname.rstrip(".").lower()

        if hostname == "localhost" or hostname.endswith(".localhost"):
            return False

        try:
            addresses = [ipaddress.ip_address(hostname)]
        except ValueError:
            addresses = [
                ipaddress.ip_address(item[4][0])
                for item in socket.getaddrinfo(
                    hostname,
                    port or (443 if parsed.scheme.lower() == "https" else 80),
                    type=socket.SOCK_STREAM,
                )
            ]

        return bool(addresses) and all(
            address.is_global for address in addresses
        )

    except (ValueError, TypeError, OverflowError, OSError):
        return False


def _safe_get(url, timeout, max_redirects=5):
    """Validate each destination before making an HTTP request."""

    current_url = url

    with requests.Session() as session:
        for redirect_count in range(max_redirects + 1):
            if not _validate_public_url(current_url):
                raise requests.RequestException(
                    "URL is invalid or resolves to a non-public destination."
                )

            response = session.get(
                current_url,
                timeout=timeout,
                allow_redirects=False,
            )

            if response.status_code not in (301, 302, 303, 307, 308):
                return response

            location = response.headers.get("Location")
            response.close()

            if not location:
                raise requests.RequestException(
                    "Redirect response has no Location header."
                )

            if redirect_count >= max_redirects:
                raise requests.RequestException(
                    "Maximum redirect count exceeded."
                )

            current_url = urljoin(current_url, location)

    raise requests.RequestException("Unable to complete request.")


def scan_web_target(url, timeout=5):
    """Perform a passive web-security configuration assessment."""

    if not isinstance(url, str) or not url.strip():
        return {"url": url, "error": "A valid URL is required."}

    url = url.strip()

    if "://" not in url:
        url = "https://" + url

    try:
        parsed_url = urlsplit(url)

        if parsed_url.scheme.lower() not in ("http", "https"):
            return {
                "url": url,
                "error": "Only HTTP and HTTPS URLs are supported.",
            }

        if not parsed_url.hostname:
            return {"url": url, "error": "The URL must include a hostname."}

        _ = parsed_url.port

        if parsed_url.username is not None or parsed_url.password is not None:
            return {
                "url": url,
                "error": "URLs containing embedded credentials are not allowed.",
            }

        timeout = float(timeout)

        if not 0 < timeout <= 30:
            return {
                "url": url,
                "error": "Timeout must be greater than 0 and at most 30 seconds.",
            }

    except (ValueError, TypeError, OverflowError):
        return {"url": url, "error": "Invalid URL or timeout value."}

    try:
        response = _safe_get(url, timeout)
    except requests.RequestException as error:
        return {"url": url, "error": str(error)}

    findings = []
    headers = response.headers

    for header, description in SECURITY_HEADERS.items():
        if header not in headers:
            findings.append({
                "type": "Missing Security Header",
                "header": header,
                "description": description,
            })

    cookies = []

    for cookie in response.cookies:
        cookies.append({
            "name": cookie.name,
            "secure": cookie.secure,
            "httponly": "HttpOnly" in cookie._rest,
            "samesite": cookie._rest.get("SameSite"),
        })

    if response.url.startswith("http://"):
        findings.append({
            "type": "HTTPS",
            "description": "Target is using HTTP instead of HTTPS.",
        })

    return {
        "requested_url": url,
        "final_url": response.url,
        "status_code": response.status_code,
        "https": response.url.startswith("https://"),
        "server": headers.get("Server"),
        "security_headers": {
            header: headers.get(header)
            for header in SECURITY_HEADERS
        },
        "cookies": cookies,
        "findings": findings,
    }


def print_web_summary(result):
    """Display web-security scan results."""

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