"""External API call — should be detected as execution."""
import requests

def search_api(query: str) -> dict:
    resp = requests.get("https://api.search.com/v1", params={"q": query})
    return resp.json()

def post_result(data: dict) -> None:
    requests.post("https://api.internal.com/results", json=data)
