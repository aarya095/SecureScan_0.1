import json
from urllib.parse import urlparse


class URLSecurityScanner:
    """A class to validate URLs and check if they use HTTP or HTTPS."""

    def __init__(self, mapped_data_file="mapped_data.json", results_file="security_scan_results.json"):
        self.mapped_data_file = mapped_data_file
        self.results_file = results_file
        self.urls = set()  # Store unique URLs
        self.results = {}

    def validate_url(self, url):
        """Ensure the URL is valid and formatted correctly."""
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url  # Default to HTTP if no scheme is provided
        parsed_url = urlparse(url)
        if not parsed_url.netloc:
            raise ValueError("Invalid URL format.")
        return url

    def extract_protocol(self, url):
        """Determine if the URL is using HTTP or HTTPS."""
        parsed_url = urlparse(url)
        protocol = parsed_url.scheme.upper()  # Extract 'http' or 'https' and convert to uppercase
        is_secure = protocol == "HTTPS"
        return protocol, is_secure

    def load_urls_from_json(self):
        """Load target URLs from a JSON file."""
        try:
            with open(self.mapped_data_file, "r") as file:
                data = json.load(file)

            self.urls.add(self.validate_url(data["target_url"]))

            for page in data.get("pages", []):
                self.urls.add(self.validate_url(page["url"]))
                for link in page.get("links", []):
                    self.urls.add(self.validate_url(link))

        except (FileNotFoundError, json.JSONDecodeError) as e:
            print(f"Error loading JSON file: {e}")

    def scan_urls(self):
        """Perform the security check for HTTP/HTTPS protocols."""
        print("\n🔹 Scanning URLs...")

        if not self.urls:
            print("No URLs found in mapped_data.json")
            return

        for url in self.urls:
            protocol, is_secure = self.extract_protocol(url)
            self.results[url] = {"protocol": protocol, "secure": is_secure}
            print(f"{url} -> {protocol}")

    def save_results(self):
        """Save the results of the HTTP/HTTPS check to a JSON file."""
        with open(self.results_file, "w") as file:
            json.dump(self.results, file, indent=4)
        print("\n✅ HTTP/HTTPS check complete! Results saved in security_scan_results.json")

    def run(self):
        """Main method to execute the URL security scan."""
        self.load_urls_from_json()
        self.scan_urls()
        self.save_results()


if __name__ == "__main__":
    scanner = URLSecurityScanner()
    scanner.run()
