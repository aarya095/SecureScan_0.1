import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import json

def crawl_website(url, base_url, collected_data=[]):
    """ Recursively crawl all internal links and collect form details """
    if url in {entry['url'] for entry in collected_data}:
        return  # Avoid duplicates

    try:
        response = requests.get(url)
        if response.status_code != 200:
            return

        soup = BeautifulSoup(response.text, "html.parser")

        # Extract forms and input fields
        forms = soup.find_all("form")
        for form in forms:
            action = form.get("action")
            method = form.get("method", "GET").upper()
            full_action_url = urljoin(url, action) if action else url
            inputs = [inp.get("name") for inp in form.find_all("input") if inp.get("name")]

            collected_data.append({
                "url": full_action_url,
                "method": method,
                "inputs": inputs
            })

        # Extract and crawl internal links
        for link in soup.find_all("a", href=True):
            full_url = urljoin(url, link.get("href"))
            if urlparse(full_url).netloc == urlparse(base_url).netloc:
                crawl_website(full_url, base_url, collected_data)

    except requests.RequestException as e:
        print(f"Error fetching {url}: {e}")

    return collected_data  # Return collected data

# Example Usage
target_website = "http://localhost:3000"  # Change to your target
print(f"🌍 Starting Website Mapping: {target_website}\n")
mapped_data = crawl_website(target_website, target_website)

# Save to JSON file for scanners to use
with open("mapped_data.json", "w") as f:
    json.dump(mapped_data, f, indent=4)

print("\n✅ Website mapping completed and saved to mapped_data.json")
