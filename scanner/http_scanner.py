import json
from urllib.parse import urlparse

def validate_url(url):
    """Ensure the URL is valid and formatted correctly."""
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url  # Default to HTTP if no scheme is provided
    parsed_url = urlparse(url)
    if not parsed_url.netloc:
        raise ValueError("Invalid URL format.")
    return url

def extract_protocol(url):
    """Determine if the URL is using HTTP or HTTPS."""
    parsed_url = urlparse(url)
    protocol = parsed_url.scheme.upper()  # Extract 'http' or 'https' and convert to uppercase
    is_secure = protocol == "HTTPS"
    return protocol, is_secure

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
    """Run the HTTP/HTTPS security scanner using local data."""
    print("\n🔹 Scanning...")

    urls = load_urls_from_json()

    if not urls:
        print("No URLs found in mapped_data.json")
        return
    
    results = {}
    for url in urls:
        protocol, is_secure = extract_protocol(url)
        results[url] = {"protocol": protocol, "secure": is_secure}
        print(f"{url} -> {protocol}")

    with open("security_scan_results.json", "w") as file:
        json.dump(results, file, indent=4)

    print("\n✅ HTTP/HTTPS check complete! Results saved in security_scan_results.json")

# Ensure this script runs only when executed directly (not when imported)
if __name__ == "__main__":
    run()
