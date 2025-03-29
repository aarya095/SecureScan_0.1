import json
import sys
import os
import time
import subprocess
from urllib.parse import urljoin, urlparse
from playwright.sync_api import sync_playwright

class WebCrawler:
    def __init__(self, target_url, mode="full_scan", selected_scanners=None, max_depth=2, max_pages=50):
        """
        Initialize the WebCrawler.
        - `mode`: "full_scan" (runs all scanners) or "custom_scan" (runs selected scanners).
        - `selected_scanners`: List of scanners (used only in custom scans).
        """
        self.target_url = target_url
        self.mode = mode 
        self.selected_scanners = selected_scanners or []
        self.max_depth = max_depth
        self.max_pages = max_pages
        self.visited_links = set()
        self.mapped_data = {"target_url": target_url, "pages": []}
        self.results_file = "mapped_data.json"

    def extract_links(self, page, base_url):
        """Extracts all valid internal links from the page."""
        links = set()
        for link in page.locator("a").all():
            href = link.get_attribute("href")
            if href:
                absolute_url = urljoin(base_url, href)
                parsed_absolute = urlparse(absolute_url)
                parsed_base = urlparse(base_url)

                if parsed_absolute.netloc == parsed_base.netloc and absolute_url not in self.visited_links:
                    links.add(absolute_url)

        return list(links)

    def extract_forms(self, page, base_url):
        """Extracts form details from the page."""
        forms = []
        for form in page.locator("form").all():
            action = form.get_attribute("action") or base_url
            method = form.get_attribute("method") or "GET"

            inputs = []
            for input_element in form.locator("input, textarea, select").all():
                input_name = input_element.get_attribute("name")
                if input_name:
                    inputs.append(input_name)

            forms.append({
                "action": urljoin(base_url, action),
                "method": method.upper(),
                "inputs": inputs
            })

        return forms

    def visit_page(self, page, url, base_url, depth):
        """Visits a page and extracts links and forms."""
        if depth > self.max_depth or url in self.visited_links or len(self.mapped_data["pages"]) >= self.max_pages:
            return

        print(f"\n🔍 Crawling: {url} (Depth: {depth})")
        self.visited_links.add(url)

        try:
            page.goto(url, wait_until="domcontentloaded", timeout=15000)

            page.evaluate("window.scrollTo(0, document.body.scrollHeight)")
            page.wait_for_timeout(1500)

            page_data = {
                "url": url,
                "links": self.extract_links(page, base_url),
                "forms": self.extract_forms(page, base_url)
            }

            self.mapped_data["pages"].append(page_data)

            for link in page_data["links"]:
                if len(self.mapped_data["pages"]) < self.max_pages:
                    self.visit_page(page, link, base_url, depth + 1)

        except Exception as e:
            print(f"❌ Error crawling {url}: {e}")

    def crawl(self):
        """Main function to start crawling a website."""
        print("\n🚀 Starting Web Crawler...")
        start_time = time.time()

        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            page = browser.new_page()
            page.set_extra_http_headers({"User-Agent": "Chromium (compatible; WebCrawler/1.0)"})

            try:
                self.visit_page(page, self.target_url, self.target_url, 0)
            finally:
                browser.close()

        crawl_time = time.time() - start_time
        print(f"\n✅ Crawling Complete! Time: {crawl_time:.2f} seconds")

        # ✅ Store crawled data in mapped_data.json
        self.store_crawl_results(crawl_time)

        # ✅ Trigger scanners after crawling
        self.run_scanners()

    def store_crawl_results(self, crawl_time):
        """Saves crawling results into a JSON file."""
        self.mapped_data["execution_time"] = round(crawl_time, 2)

        with open(self.results_file, "w") as file:
            json.dump(self.mapped_data, file, indent=4)

        print(f"\n✅ Crawling results saved to {self.results_file}")

    def run_scanners(self):
        """Runs the appropriate scanner script after crawling."""
        script_to_run = "scanner/run_all_scanners.py" if self.mode == "custom_scan" else "scanner/run_selected_scanners.py"
        
        print(f"\n🚀 Running Scanners... (Mode: {self.mode})")
        
        try:
            if self.mode == "custom_scan":
                # Pass selected scanners to the script
                scanner_args = " ".join(self.selected_scanners)
                subprocess.run(["python", script_to_run, self.results_file, scanner_args], check=True)
            else:
                subprocess.run(["python", script_to_run, self.results_file], check=True)
            
            print(f"\n✅ Scanners executed successfully!")

        except subprocess.CalledProcessError as e:
            print(f"❌ Error running scanner script: {e}")

if __name__ == "__main__":
    if len(sys.argv) > 1:
        target_url = sys.argv[1]
    else:
        target_url = input("Enter the target URL (e.g., http://example.com): ").strip()

    if not target_url.startswith("http"):
        print("❌ Invalid URL! Make sure to include 'http://' or 'https://'.")
    else:
        # Detect whether running a full scan or custom scan
        mode = "full_scan"
        selected_scanners = []

        crawler = WebCrawler(target_url, mode, selected_scanners)
        crawler.crawl()
