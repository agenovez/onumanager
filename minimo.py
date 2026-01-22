import requests
import hashlib

ONU_IP = "172.31.0.28"   # o 172.31.0.28 según su red
USERNAME = "adminisp"
PASSWORD = "adminisp"      # la clave real en texto

def md5_hex(s: str) -> str:
    # OJO: sin espacios, sin saltos de línea
    return hashlib.md5(s.encode("utf-8")).hexdigest()

print("DEBUG MD5(password) =", md5_hex(PASSWORD))  # debe imprimir 096bf511...

session = requests.Session()
payload = {
    "module": "login",
    "username": USERNAME,
    "encryPassword": md5_hex(PASSWORD)
}

r = session.post(f"http://{ONU_IP}/post.json", json=payload, timeout=5)

print("HTTP", r.status_code)
print("RESP", r.text)
print("COOKIES", session.cookies.get_dict())
