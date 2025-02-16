import requests
response1 = requests.get("https://youtube.com")
print(response1.status_code)  # 200 = Success, 403/401 = Forbidden
