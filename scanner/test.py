import requests

response = requests.get("https://example.com", timeout=5)
print(response.status_code)  # Prints HTTP status code (e.g., 200 for success)
print(response.text)  # Prints the HTML content of the page
