from drf_gnap.signatures import sign_request
import requests

url = "http://127.0.0.1:8000/payment/"

headers = sign_request(
    method="GET",
    url=url,
    headers={},
    body=b"",
    key="test-key"
)

print("Generated Headers:", headers)

response = requests.get(url, headers=headers)

print("Status Code:", response.status_code)
print("Response:", response.text)