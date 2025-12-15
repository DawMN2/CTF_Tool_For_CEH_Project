#!/usr/bin/env python3
"""
AuthScope v2
CTF / Lab tool to:
- Auto-authenticate (login)
- Grab JWT automatically
- Analyze JWT (alg=none, claims)
- Enumerate cookies + headers
- Export nuclei inputs

Usage example:
python authscope.py \
  --url http://api.local/admin/data \
  --auth-login http://api.local/auth/login \
  --username alice \
  --password alice123 \
  --unsigned
"""

import argparse
import requests
import re
import sys
import csv
import json
import base64
import time
from urllib.parse import urlparse

JWT_RE = re.compile(r'([A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{0,})')

# ------------------------
# Helpers
# ------------------------

def b64decode_nopad(data: str):
    data += '=' * (-len(data) % 4)
    return base64.urlsafe_b64decode(data.encode())

def pretty(obj):
    try:
        return json.dumps(obj, indent=2)
    except:
        return str(obj)

def decode_jwt(token):
    info = {}
    parts = token.split('.')
    info['parts'] = len(parts)

    try:
        info['header'] = json.loads(b64decode_nopad(parts[0]))
    except Exception as e:
        info['header_error'] = str(e)

    try:
        if len(parts) > 1 and parts[1]:
            info['payload'] = json.loads(b64decode_nopad(parts[1]))
    except Exception as e:
        info['payload_error'] = str(e)

    return info

def analyze_token(token):
    decoded = decode_jwt(token)
    notes = []

    hdr = decoded.get('header', {})
    payload = decoded.get('payload', {})

    alg = hdr.get('alg') if isinstance(hdr, dict) else None
    if alg:
        notes.append(f"alg: {alg}")
        if str(alg).lower() == "none":
            notes.append("WARNING: alg=none (unsigned JWT)")
    else:
        notes.append("No alg found in JWT header")

    if 'exp' in payload:
        if payload['exp'] < int(time.time()):
            notes.append("Token appears EXPIRED")

    if 'iss' not in payload:
        notes.append("Missing 'iss' claim")
    if 'aud' not in payload:
        notes.append("Missing 'aud' claim")
    if 'kid' not in hdr:
        notes.append("Missing 'kid' header")

    return decoded, notes

def find_jwts(text):
    return list(set(JWT_RE.findall(text or "")))

def analyze_cookies(resp):
    results = []
    for c in resp.cookies:
        results.append({
            "name": c.name,
            "httponly": "HttpOnly" in c._rest,
            "secure": c.secure,
            "samesite": c._rest.get("SameSite")
        })
    return results

# ------------------------
# Auto Auth
# ------------------------

def perform_login(url, username, password, unsigned, headers, timeout):
    payload = {
        "username": username,
        "password": password
    }
    if unsigned:
        payload["unsigned"] = True

    r = requests.post(url, json=payload, headers=headers, timeout=timeout)
    if r.status_code != 200:
        print(f"[!] Login failed ({r.status_code})")
        return None

    token = r.json().get("token")
    if not token:
        print("[!] No token in login response")
        return None

    print("[+] Login successful, JWT acquired")
    return token

# ------------------------
# Main
# ------------------------

def main():
    parser = argparse.ArgumentParser(description="AuthScope v2 — JWT & Auth Analysis Tool")

    parser.add_argument("--url", "-u", required=True, help="Target URL")
    parser.add_argument("--user-agent", default="AuthScope/2.0")
    parser.add_argument("--timeout", type=int, default=15)

    # Auth options
    parser.add_argument("--auth-login", help="Login endpoint URL")
    parser.add_argument("--username", help="Auth username")
    parser.add_argument("--password", help="Auth password")
    parser.add_argument("--unsigned", action="store_true", help="Request unsigned JWT (alg=none)")

    # Export
    parser.add_argument("--export", "-e", help="Export nuclei CSV")

    args = parser.parse_args()

    headers = {"User-Agent": args.user_agent}
    token = None

    # ---- Auto Auth ----
    if args.auth_login:
        if not args.username or not args.password:
            print("[!] Auth requires --username and --password")
            sys.exit(1)

        token = perform_login(
            args.auth_login,
            args.username,
            args.password,
            args.unsigned,
            headers,
            args.timeout
        )

        if token:
            headers["Authorization"] = f"Bearer {token}"
            decoded, notes = analyze_token(token)

            print("\n[+] JWT Analysis (login token)")
            print("Header:")
            print(pretty(decoded.get("header", {})))
            print("Payload:")
            print(pretty(decoded.get("payload", {})))
            print("Notes:")
            for n in notes:
                print(" -", n)
            print("\n" + "-"*40)

    # ---- Main Request ----
    resp = requests.get(args.url, headers=headers, timeout=args.timeout, allow_redirects=True)

    print(f"\n[*] {args.url} → HTTP {resp.status_code}\n")

    # Cookies
    cookies = analyze_cookies(resp)
    if cookies:
        print("[+] Cookies:")
        for c in cookies:
            flags = []
            if c["httponly"]: flags.append("HttpOnly")
            if c["secure"]: flags.append("Secure")
            if c["samesite"]: flags.append(f"SameSite={c['samesite']}")
            print(f"  {c['name']} → {', '.join(flags) if flags else 'NO FLAGS'}")
    else:
        print("[*] No cookies detected")

    # JWT discovery
    found = []

    for c in resp.cookies:
        found.extend(find_jwts(c.value))

    for k, v in resp.headers.items():
        found.extend(find_jwts(v))

    found.extend(find_jwts(resp.text))

    found = list(set(found))

    if found:
        print(f"\n[+] Found {len(found)} JWT-like tokens\n")
        for tok in found:
            decoded, notes = analyze_token(tok)
            print("Token:", tok)
            print("Header:", pretty(decoded.get("header", {})))
            print("Payload:", pretty(decoded.get("payload", {})))
            print("Notes:")
            for n in notes:
                print(" -", n)
            print("\n" + "-"*40)
    else:
        print("\n[*] No JWTs discovered")

    # Export
    if args.export:
        parsed = urlparse(args.url)
        with open(args.export, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=["url", "host", "auth_header", "sample_token"])
            writer.writeheader()
            writer.writerow({
                "url": args.url,
                "host": f"{parsed.scheme}://{parsed.netloc}",
                "auth_header": "Authorization: Bearer {{TOKEN}}",
                "sample_token": token or ""
            })
        print(f"[+] Exported nuclei CSV → {args.export}")

if __name__ == "__main__":
    main()
