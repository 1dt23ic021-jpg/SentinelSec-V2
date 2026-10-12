def detect_service(port, banner=None):
    """
    Identify a likely network service using
    the port number and optional banner.
    """
    if banner:
        banner_lower = banner.lower()

        if "openssh" in banner_lower:
            return "SSH"

        if "apache" in banner_lower:
            return "HTTP - Apache"

        if "nginx" in banner_lower:
            return "HTTP - Nginx"

        if "microsoft-iis" in banner_lower:
            return "HTTP - Microsoft IIS"

        if "simplehttp" in banner_lower:
            return "HTTP - Python SimpleHTTP"

    common_services = {
        20: "FTP Data",
        21: "FTP",
        22: "SSH",
        23: "Telnet",
        25: "SMTP",
        53: "DNS",
        80: "HTTP",
        110: "POP3",
        143: "IMAP",
        443: "HTTPS",
        445: "SMB",
        3306: "MySQL",
        5432: "PostgreSQL",
        6379: "Redis",
        8080: "HTTP Proxy / Alternate HTTP",
    }

    return common_services.get(port, "Unknown")