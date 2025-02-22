import json
import time
import sys
from urllib.parse import urljoin, urlparse
from playwright.sync_api import sync_playwright

# Set to store visited links to avoid infinite loops
visited_links = set()

def crawl_website(target_url, max_depth=2, max_pages=50):

    visited_links = set()
    mapped_data = {"target_url": target_url, "pages": []}
    total_pages_crawled = 0
    
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)  
        page = browser.new_page()

        page.set_extra_http_headers({"User-Agent": "Chromium (compatible; WebCrawler/0.1)"})
        
        def visit_page(url, depth=0):
            nonlocal total_pages_crawled
            
            if depth > max_depth or url in visited_links or total_pages_crawled >= max_pages:
                return  # Stop recursion if depth exceeded or URL already visited
            
            print(f"\n Crawling: {url} (Depth: {depth})")
            visited_links.add(url)
            total_pages_crawled += 1  # Mark as visited
            
            try:
                page.goto(url, wait_until="networkidle", timeout=10000)  # Wait for JS content to load
                time.sleep(2)  # Small delay to allow all elements to load

                page_data = {"url": url, "links": [], "forms": []}

                # Scroll to bottom to load lazy-loaded content
                page.evaluate("window.scrollTo(0, document.body.scrollHeight)")
                time.sleep(1)

                # Extract Links
                for link in page.locator("a").all():
                    href = link.get_attribute("href")
                    if href:
                        absolute_url = urljoin(url, href)  # Convert relative URLs to absolute
                        if urlparse(absolute_url).netloc == urlparse(target_url).netloc:
                            if absolute_url not in visited_links: 
                                page_data["links"].append(absolute_url)

                # Extract Forms
                for form in page.locator("form").all():
                    action = form.get_attribute("action") or url  # Default to current page
                    method = form.get_attribute("method") or "GET"

                    inputs = []
                    for input_element in form.locator("input, textarea, select").all():
                        input_name = input_element.get_attribute("name")
                        if input_name:
                            inputs.append(input_name)

                    page_data["forms"].append({
                        "action": urljoin(url, action),
                        "method": method.upper(),
                        "inputs": inputs
                    })

                mapped_data["pages"].append(page_data)

                # Recursively crawl discovered links
                for link in page_data["links"]:
                    visit_page(link, depth + 1)

            except Exception as e:
                print(f" Error crawling {url}: {e}")

        try:
            visit_page(target_url)  # Start crawling from the root URL
        finally:

        # Save results to mapped_data.json
            with open("mapped_data.json", "w") as f:
                json.dump(mapped_data, f, indent=4)

            browser.close()
            print("\n Website Mapping Complete! Data saved to mapped_data.json")

# Get target URL from the user
if __name__ == "__main__":
    if len(sys.argv) > 1:
        target_url = sys.argv[1]
    else:
        target_url = input("Enter the target URL (e.g., http://example.com): ")
        
    crawl_website(target_url)
