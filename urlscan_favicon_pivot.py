"""
urlscan.io favicon pivoting (free-tier, exact-hash based).
"""

import sys
import time
import os
import requests

try:
    from dotenv import load_dotenv
except ImportError:
    def load_dotenv():
        return False

load_dotenv()

API_BASE = "https://urlscan.io/api/v1"
API_KEY = os.getenv("URLSCAN_API_KEY", "")


def headers():
    return {"API-Key": API_KEY, "Content-Type": "application/json"}


def find_existing_scan(domain: str) -> str | None:
    resp = requests.get(
        f"{API_BASE}/search/",
        headers=headers(),
        params={"q": f'page.domain:"{domain}"', "size": 1},
    )
    resp.raise_for_status()
    results = resp.json().get("results", [])
    return results[0]["task"]["uuid"] if results else None


def submit_scan(domain: str) -> str:
    resp = requests.post(
        f"{API_BASE}/scan/",
        headers=headers(),
        json={"url": f"https://{domain}", "visibility": "public"},
    )
    resp.raise_for_status()
    return resp.json()["uuid"]


def wait_for_result(uuid: str, timeout: int = 60) -> dict:
    deadline = time.time() + timeout
    while time.time() < deadline:
        resp = requests.get(f"{API_BASE}/result/{uuid}/", headers=headers())
        if resp.status_code == 200:
            return resp.json()
        time.sleep(3)
    sys.exit("Scan did not finish in time, try again later.")


def extract_favicon_hash(result: dict) -> str | None:
    for entry in result.get("data", {}).get("requests", []):
        url = entry.get("request", {}).get("request", {}).get("url", "")
        if "favicon" in url.lower():
            return entry.get("response", {}).get("hash")
    return None


def search_by_hash(file_hash: str, size: int = 50):
    resp = requests.get(
        f"{API_BASE}/search/",
        headers=headers(),
        params={"q": f'hash:"{file_hash}"', "size": size},
    )
    resp.raise_for_status()
    return resp.json().get("results", [])


def main():
    domain = "sky.com"

    print(f"[+] Looking for an existing scan of {domain}...")
    uuid = find_existing_scan(domain)
    if not uuid:
        print("[+] None found, submitting a fresh scan...")
        uuid = submit_scan(domain)

    print(f"[+] Fetching scan result {uuid}...")
    result = wait_for_result(uuid)

    favicon_hash = extract_favicon_hash(result)
    if not favicon_hash:
        sys.exit("Could not locate a favicon request in this scan's HTTP transactions.")

    print(f"[+] Favicon SHA256: {favicon_hash}")
    print(f"[+] Searching urlscan.io for other scans with this exact favicon...\n")

    matches = search_by_hash(favicon_hash)
    print(f"[+] {len(matches)} matching scans:\n")
    for m in matches:
        page = m.get("page", {})
        print(f"  {page.get('domain'):<35} scanned={m.get('task', {}).get('time')}  "
              f"url={page.get('url')}")


if __name__ == "__main__":
    main()
