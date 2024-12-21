import re
import json
from collections import Counter

def parse_log(log_data):
    """Parse the log data to extract URLs and their HTTP status codes."""
    url_status_pattern = re.compile(r'\"[A-Z]+ (?P<url>https?://[^\s]+) HTTP/[^\"]+\" (?P<status>\d{3})')
    url_status_list = []

    for line in log_data:
        match = url_status_pattern.search(line)
        if match:
            url_status_list.append((match.group('url'), match.group('status')))
    return url_status_list

def filter_404(url_status_list):
    """Filter out URLs with a 404 status code and count their occurrences."""
    filtered = [url for url, status in url_status_list if status == '404']
    return Counter(filtered)

def print_url_status_report(url_status_list):
    """Print the list of URLs and their status codes."""
    print("URL Status Report:")
    for url, status in url_status_list:
        print(f"URL: {url}, Status Code: {status}")

def print_malware_candidates(counter_404):
    """Print 404 error URLs and their counts."""
    print("\nMalware Candidates (404 URLs):")
    for url, count in counter_404.items():
        print(f"URL: {url}, 404 Count: {count}")

def parse_blacklist_domains(html_content):
    """Extract blacklisted domains from the provided HTML content using regular expressions."""
    domains = re.findall(r'<domain>(.*?)</domain>', html_content)
    return [domain.strip() for domain in domains]

def match_blacklist(url_status_list, blacklist):
    """Match URLs against the blacklisted domains."""
    matched = [(url, status) for url, status in url_status_list if any(domain in url for domain in blacklist)]
    return matched

def print_alert_json(matched_list):
    """Print matched URLs and their details in a JSON-like format."""
    alerts = [
        {"url": url, "status": status, "count": matched_list.count((url, status))}
        for url, status in set(matched_list)
    ]
    print("\nAlert JSON:")
    print(json.dumps(alerts, indent=4))

def print_summary_json(total_urls, total_404, total_matched):
    """Print a summary report in JSON-like format."""
    summary = {
        "total_urls": total_urls,
        "total_404_urls": total_404,
        "total_blacklist_matched": total_matched
    }
    print("\nSummary JSON:")
    print(json.dumps(summary, indent=4))

def main():
    # Simulated log data
    log_data = [
        '192.168.1.100 - - [05/Dec/2024:09:15:10 +0000] "GET http://malicious-site.com/page1 HTTP/1.1" 404 4321',
        '192.168.1.100 - - [05/Dec/2024:09:16:10 +0000] "GET http://example.com/page1 HTTP/1.1" 200 2123',
        '192.168.1.101 - - [05/Dec/2024:09:17:15 +0000] "GET http://malicious-site.com/page2 HTTP/1.1" 404 1234',
        '192.168.1.102 - - [05/Dec/2024:09:18:20 +0000] "GET http://example.com/page3 HTTP/1.1" 200 3421',
        '192.168.1.100 - - [05/Dec/2024:09:19:30 +0000] "GET http://example.com/page2 HTTP/1.1" 404 3123'
    ]

    # Simulating HTML content for blacklist domains
    html_content = """
    <domain>malicious-site.com</domain>
    <domain>example.com</domain>
    """
    
    # Parse the log data
    url_status_list = parse_log(log_data)

    # Filter out 404 URLs
    counter_404 = filter_404(url_status_list)

    # Print URL status report
    print_url_status_report(url_status_list)

    # Print malware candidates (404 URLs)
    print_malware_candidates(counter_404)

    # Parse blacklist domains from HTML content
    blacklist = parse_blacklist_domains(html_content)

    # Match URLs with blacklisted domains
    matched_list = match_blacklist(url_status_list, blacklist)

    # Print matched URLs in a JSON-like format
    print_alert_json(matched_list)

    # Print the summary report
    print_summary_json(len(url_status_list), len(counter_404), len(matched_list))

if __name__ == "__main__":
    main()