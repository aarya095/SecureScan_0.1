import json
import sys
import time
from urllib.parse import urljoin, urlparse
from playwright.sync_api import sync_playwright

# Global set to store visited links to avoid duplicate crawling
visited_links = set()

def extract_links(page, base_url):
    """Extracts and returns a list of unique internal links from the page."""
    links = set()
    for link in page.locator("a").all():
        href = link.get_attribute("href")
        if href:
            absolute_url = urljoin(base_url, href)
            parsed_absolute = urlparse(absolute_url)
            parsed_base = urlparse(base_url)

            # Ensure the link belongs to the same domain and is not visited
            if parsed_absolute.netloc == parsed_base.netloc and absolute_url not in visited_links:
                links.add(absolute_url)
    
    return list(links)

def extract_forms(page, base_url):
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

def visit_page(page, url, base_url, depth, max_depth, max_pages, mapped_data):
    """Recursively visits pages, extracts data, and respects depth/page limits."""
    global visited_links
    if depth > max_depth or url in visited_links or len(mapped_data["pages"]) >= max_pages:
        return

    print(f"\n🔍 Crawling: {url} (Depth: {depth})")
    visited_links.add(url)

    try:
        page.goto(url, wait_until="domcontentloaded", timeout=15000)  # 15 seconds timeout

        # Scroll down to load dynamic content
        page.evaluate("window.scrollTo(0, document.body.scrollHeight)")
        page.wait_for_timeout(1500)  # Wait for lazy-loaded elements

        # Extract data
        page_data = {
            "url": url,
            "links": extract_links(page, base_url),
            "forms": extract_forms(page, base_url)
        }

        mapped_data["pages"].append(page_data)

        # Recursively visit extracted links
        for link in page_data["links"]:
            visit_page(page, link, base_url, depth + 1, max_depth, max_pages, mapped_data)

    except Exception as e:
        print(f"❌ Error crawling {url}: {e}")

def crawl_website(target_url, max_depth=2, max_pages=50):
    """Main function to start the crawling process."""
    mapped_data = {"target_url": target_url, "pages": []}

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page()
        page.set_extra_http_headers({"User-Agent": "Chromium (compatible; WebCrawler/1.0)"})

        try:
            visit_page(page, target_url, target_url, 0, max_depth, max_pages, mapped_data)
        finally:
            with open("mapped_data.json", "w") as f:
                json.dump(mapped_data, f, indent=4)

            browser.close()
            print("\n✅ Website Mapping Complete! Data saved to mapped_data.json")

if __name__ == "__main__":
    if len(sys.argv) > 1:
        target_url = sys.argv[1]
    else:
        target_url = input("Enter the target URL (e.g., http://example.com): ").strip()

    if not target_url.startswith("http"):
        print("❌ Invalid URL! Make sure to include 'http://' or 'https://'.")
    else:
        crawl_website(target_url)
