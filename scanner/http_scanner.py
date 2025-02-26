import json
import requests
from urllib.parse import urlparse

def validate_url(url):
    """Ensure the URL is valid and formatted correctly."""
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    parsed_url = urlparse(url)
    if not parsed_url.netloc:
        raise ValueError("Invalid URL format.")
    return url

def check_http_https(url):
    """Check if the URL uses HTTP or HTTPS."""
    try:
        response = requests.get(url, timeout=5)
        if response.url.startswith('https://'):
            return 'HTTPS', True
        else:
            return 'HTTP', False
    except requests.RequestException as e:
        return f"Error: {e}", False

def load_urls_from_json(filename="mapped_data.json"):
    """Load target URLs from a JSON file."""
    try:
        with open(filename, "r") as file:
            data = json.load(file)

        urls = set()
        urls.add(validate_url(data["target_url"]))

        for page in data.get("pages", []):
            urls.add(validate_url(page["url"]))
            for link in page.get("links", []):
                urls.add(validate_url(link))

        return list(urls)
    except (FileNotFoundError, json.JSONDecodeError) as e:
        print(f"Error loading JSON file: {e}")
        return []

def run():
    """Run the HTTP/HTTPS security scanner."""
    print("\n🔹 Scanning...")

    urls = load_urls_from_json()

    if not urls:
        print("No URLs found in mapped_data.json")
        return
    
    results = {}
    for url in urls:
        status, is_secure = check_http_https(url)
        results[url] = {"protocol": status, "secure": is_secure}
        print(f"{url} -> {status}")

    with open("security_scan_results.json", "w") as file:
        json.dump(results, file, indent=4)

    print("\n✅ HTTP/HTTPS check complete! Results saved in security_scan_results.json")

# Ensure this script runs only when executed directly (not when imported)
if __name__ == "__main__":
    run()
