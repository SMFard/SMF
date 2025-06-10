import re
from collections import defaultdict
from datetime import datetime, time

# Regex patterns for phishing URL detection (example patterns)
PHISHING_PATTERNS = [
    r"login[-.]?secure",  # login-secure or login.secure
    r"account[-.]?verify",
    r"update[-.]?password",
    r"banking[-.]?alert",
    r"confirm[-.]?identity",
    r"secure[-.]?access",
    r"webscr",  # common phishing pattern in URLs
    r"signin[-.]?account",
]

# Blacklisted IPs example (could be loaded from DB)
BLACKLISTED_IPS = set()

# Threshold for failed login attempts
FAILED_LOGIN_THRESHOLD = 5

# Threshold for port scan detection (number of sequential ports accessed)
PORT_SCAN_THRESHOLD = 10

# Sensitive files or restricted resources patterns
SENSITIVE_FILE_PATTERNS = [
    r"/etc/passwd",
    r"/etc/shadow",
    r"/admin",
    r"/config",
    r"/wp-admin",
    r"/.git",
]

def is_phishing_url(url):
    """
    Check if the URL matches any phishing patterns.
    """
    url = url.lower()
    for pattern in PHISHING_PATTERNS:
        if re.search(pattern, url):
            return True
    return False

def is_valid_email(email):
    """
    Basic email format validation.
    """
    pattern = r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$"
    return re.match(pattern, email) is not None

def is_valid_website(url):
    """
    Basic website URL validation.
    """
    pattern = r"^(https?:\/\/)?([\w\-]+\.)+[\w\-]+(\/[\w\-./?%&=]*)?$"
    return re.match(pattern, url) is not None

def detect_emails(text):
    """
    Detect all email addresses in the given text.
    Returns a list of email addresses found.
    """
    pattern = r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+"
    return re.findall(pattern, text)

import difflib

TRUSTED_DOMAINS = {
    "gmail.com",
    "yahoo.com",
    "outlook.com",
    "hotmail.com",
    "icloud.com",
    "aol.com",
    "msn.com",
    "live.com",
}

def is_threat_email(email):
    """
    Determine if an email is potentially a threat based on trusted domains.
    1. Validate email format.
    2. Extract domain.
    3. Check domain against trusted domains.
    4. Use fuzzy matching to detect typosquatting.
    Flag as threat if domain is close to but not exactly a trusted domain.
    Returns (is_threat: bool, suggestion: Optional[str])
    """
    if not is_valid_email(email):
        return (False, None)

    domain = email.split('@')[-1].lower()

    # If domain is exactly trusted, not a threat
    if domain in TRUSTED_DOMAINS:
        return (False, None)

    # Check if domain is close to any trusted domain (typosquatting)
    close_matches = difflib.get_close_matches(domain, TRUSTED_DOMAINS, n=1, cutoff=0.8)
    if close_matches and close_matches[0] != domain:
        return (True, close_matches[0])

    return (False, None)

def analyze_log_file(filepath):
    """
    Analyze log file for intrusion attempts.
    Detect multiple failed login attempts, port scanning, access to sensitive files,
    unusual login hours, and blacklisted IP access.
    Log file format assumed: each line contains IP, timestamp, port, resource, and status.
    Example line: "192.168.1.1 [2024-06-01 12:34:56] PORT:80 /admin FAILED LOGIN"
    """
    failed_logins = defaultdict(int)
    port_accesses = defaultdict(list)  # ip -> list of ports accessed
    alerts = []

    with open(filepath, 'r') as f:
        for line in f:
            line = line.strip()
            # Extract IP
            ip_match = re.match(r"(\d+\.\d+\.\d+\.\d+)", line)
            ip = ip_match.group(1) if ip_match else None

            # Extract timestamp
            timestamp_match = re.search(r"\[(.*?)\]", line)
            timestamp_str = timestamp_match.group(1) if timestamp_match else None
            timestamp = None
            if timestamp_str:
                try:
                    timestamp = datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S")
                except ValueError:
                    pass

            # Extract port
            port_match = re.search(r"PORT:(\d+)", line)
            port = int(port_match.group(1)) if port_match else None

            # Extract resource accessed
            resource_match = re.search(r" (\/\S*) ", line)
            resource = resource_match.group(1) if resource_match else None

            # Detect emails in the line
            emails_found = detect_emails(line)
            for email in emails_found:
                alerts.append((ip, f"Email detected: {email}", "Low"))
                if is_valid_email(email):
                    alerts.append((ip, f"Valid email detected: {email}", "Low"))
                    if is_threat_email(email):
                        alerts.append((ip, f"Threat email detected: {email}", "High"))
                    else:
                        alerts.append((ip, f"Email is not a threat: {email}", "Low"))

            # Check for failed login
            if re.search(r"(FAILED LOGIN|LOGIN FAILED|ACCESS DENIED)", line, re.IGNORECASE):
                if ip:
                    failed_logins[ip] += 1

            # Check for blacklisted IP access attempts
            if ip and ip in BLACKLISTED_IPS:
                alerts.append((ip, "Access attempt from blacklisted IP", "High"))

            # Track port accesses for port scan detection
            if ip and port:
                port_accesses[ip].append(port)

            # Check for access to sensitive files
            if resource:
                for pattern in SENSITIVE_FILE_PATTERNS:
                    if re.search(pattern, resource):
                        alerts.append((ip, f"Access to sensitive resource: {resource}", "High"))

            # Check for unusual login hours (e.g., outside 6am-10pm)
            if timestamp and (timestamp.time() < time(6, 0) or timestamp.time() > time(22, 0)):
                alerts.append((ip, f"Access at unusual hour: {timestamp.time()}", "Medium"))

    # Check for multiple failed login attempts
    for ip, count in failed_logins.items():
        if count >= FAILED_LOGIN_THRESHOLD:
            alerts.append((ip, f"Multiple failed login attempts ({count})", "Medium"))

    # Check for port scanning (sequential port accesses)
    for ip, ports in port_accesses.items():
        sorted_ports = sorted(set(ports))
        sequential_count = 1
        max_seq = 1
        for i in range(1, len(sorted_ports)):
            if sorted_ports[i] == sorted_ports[i-1] + 1:
                sequential_count += 1
                max_seq = max(max_seq, sequential_count)
            else:
                sequential_count = 1
        if max_seq >= PORT_SCAN_THRESHOLD:
            alerts.append((ip, f"Port scanning detected: {max_seq} sequential ports accessed", "High"))

    return {
        'alerts': alerts,
        'summary': f"Found {len(alerts)} suspicious activities."
    }

def alert_user(message):
    """
    Placeholder alert function.
    In real system, could send email, SMS, or push notification.
    """
    print(f"ALERT: {message}")
