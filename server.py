#!/usr/bin/env python3
"""
Servidor proxy para el dashboard de Chia.
"""

import json
import os
import base64
import time
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse
import urllib.request
import urllib.parse

# ── Configuración ──────────────────────────────────────────────────────────────
SPREADSHEET_ID = "1rCLlFwT6MmzCqs2MUckNvgZeTQAwiwy5q8vbdLtSoS8"
SPREADSHEET_ID_FINANZAS = "1r-tcG3jnqV9zCW8J86iuL4vuN6k3hvM_VBiuRg6Wj-s"
PORT = int(os.environ.get("PORT", 8765))
CACHE_TTL = 300  # segundos (5 minutos)
# ───────────────────────────────────────────────────────────────────────────────

_data_cache = {"body": None, "expires": 0}
_finanzas_cache = {"body": None, "expires": 0}


def load_credentials():
    env_creds = os.environ.get("GOOGLE_CREDENTIALS")
    if env_creds:
        return json.loads(base64.b64decode(env_creds).decode("utf-8"))
    creds_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "credentials.json")
    with open(creds_path, "r") as f:
        return json.load(f)


def rsa_sign(private_key_pem, message):
    try:
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import padding
        from cryptography.hazmat.backends import default_backend
        key = serialization.load_pem_private_key(
            private_key_pem.encode(),
            password=None,
            backend=default_backend()
        )
        return key.sign(message, padding.PKCS1v15(), hashes.SHA256())
    except ImportError:
        raise RuntimeError("Ejecutá: pip install cryptography")


def make_jwt(creds):
    now = int(time.time())
    header = base64.urlsafe_b64encode(
        json.dumps({"alg": "RS256", "typ": "JWT"}).encode()
    ).rstrip(b"=")
    payload = base64.urlsafe_b64encode(
        json.dumps({
            "iss": creds["client_email"],
            "scope": "https://www.googleapis.com/auth/spreadsheets.readonly",
            "aud": "https://oauth2.googleapis.com/token",
            "iat": now,
            "exp": now + 3600
        }).encode()
    ).rstrip(b"=")

    signing_input = header + b"." + payload
    signature = rsa_sign(creds["private_key"], signing_input)
    sig_b64 = base64.urlsafe_b64encode(signature).rstrip(b"=")
    return (signing_input + b"." + sig_b64).decode()


_token_cache = {"token": None, "expires": 0}


def get_access_token():
    now = time.time()
    if _token_cache["token"] and now < _token_cache["expires"] - 60:
        return _token_cache["token"]

    creds = load_credentials()
    jwt = make_jwt(creds)

    data = urllib.parse.urlencode({
        "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
        "assertion": jwt
    }).encode()

    req = urllib.request.Request(
        "https://oauth2.googleapis.com/token",
        data=data,
        method="POST"
    )

    with urllib.request.urlopen(req) as resp:
        result = json.loads(resp.read())

    _token_cache["token"] = result["access_token"]
    _token_cache["expires"] = now + result.get("expires_in", 3600)
    return _token_cache["token"]


def fetch_sheet(sheet_name):
    token = get_access_token()
    url = f"https://sheets.googleapis.com/v4/spreadsheets/{SPREADSHEET_ID}/values/{urllib.parse.quote(chr(39) + sheet_name + chr(39), safe='')}"
    req = urllib.request.Request(url, headers={"Authorization": f"Bearer {token}"})
    try:
        with urllib.request.urlopen(req) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        body = e.read().decode()
        raise RuntimeError(f"HTTP {e.code} al leer '{sheet_name}': {body}")


def fetch_range(range_str, spreadsheet_id):
    token = get_access_token()
    url = (
        f"https://sheets.googleapis.com/v4/spreadsheets/{spreadsheet_id}"
        f"/values/{urllib.parse.quote(range_str, safe='!:')}"
        f"?valueRenderOption=UNFORMATTED_VALUE"
    )
    req = urllib.request.Request(url, headers={"Authorization": f"Bearer {token}"})
    try:
        with urllib.request.urlopen(req) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        body = e.read().decode()
        raise RuntimeError(f"HTTP {e.code} al leer '{range_str}': {body}")


def get_data():
    now = time.time()
    if _data_cache["body"] and now < _data_cache["expires"]:
        return _data_cache["body"]

    # Fetch ambas hojas en paralelo
    results = {}
    errors = {}

    def fetch(name):
        try:
            results[name] = fetch_sheet(name)
        except Exception as e:
            errors[name] = e

    threads = [
        threading.Thread(target=fetch, args=("Datos",)),
        threading.Thread(target=fetch, args=("Datos 2",)),
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    if errors:
        raise list(errors.values())[0]

    body = json.dumps({
        "datos":  results["Datos"]["values"],
        "datos2": results["Datos 2"]["values"],
    }).encode()

    _data_cache["body"] = body
    _data_cache["expires"] = now + CACHE_TTL
    return body


def get_finanzas_data():
    now = time.time()
    if _finanzas_cache["body"] and now < _finanzas_cache["expires"]:
        return _finanzas_cache["body"]

    result = fetch_range("Rentabilidad!J10:N", SPREADSHEET_ID_FINANZAS)
    body = json.dumps({"rentabilidad": result.get("values", [])}).encode()
    _finanzas_cache["body"] = body
    _finanzas_cache["expires"] = now + CACHE_TTL
    return body


class Handler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        print(format % args)

    def do_OPTIONS(self):
        self.send_response(200)
        self._cors()
        self.end_headers()

    def _cors(self):
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")

    def do_GET(self):
        parsed = urlparse(self.path)

        if parsed.path == "/data":
            try:
                body = get_data()
                self.send_response(200)
                self._cors()
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(body)
            except Exception as e:
                import traceback
                traceback.print_exc()
                self.send_response(500)
                self._cors()
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"error": str(e)}).encode())

        elif parsed.path == "/finanzas-data":
            try:
                body = get_finanzas_data()
                self.send_response(200)
                self._cors()
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(body)
            except Exception as e:
                import traceback
                traceback.print_exc()
                self.send_response(500)
                self._cors()
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"error": str(e)}).encode())

        elif parsed.path == "/":
            try:
                html_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "dashboard.html")
                with open(html_path, "rb") as f:
                    content = f.read()
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.end_headers()
                self.wfile.write(content)
            except FileNotFoundError:
                self.send_response(404)
                self.end_headers()
                self.wfile.write(b"dashboard.html not found")

        elif parsed.path == "/logo.png":
            try:
                logo_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "logo.png")
                with open(logo_path, "rb") as f:
                    content = f.read()
                self.send_response(200)
                self.send_header("Content-Type", "image/png")
                self.send_header("Cache-Control", "public, max-age=86400")
                self.end_headers()
                self.wfile.write(content)
            except FileNotFoundError:
                self.send_response(404)
                self.end_headers()
        else:
            self.send_response(404)
            self.end_headers()


if __name__ == "__main__":
    print(f"✓ Servidor corriendo en http://localhost:{PORT}")
    print(f"  Abrí http://localhost:{PORT} en tu browser")
    print(f"  Ctrl+C para detener\n")
    HTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
