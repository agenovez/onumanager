import argparse
import hashlib
import json
import os
import time
from datetime import datetime
from typing import Any, Dict, Optional

import requests


# -------------------------
# Utilidades
# -------------------------
def md5_hex(s: str) -> str:
    # Importante: sin \n ni espacios extra
    return hashlib.md5(s.encode("utf-8")).hexdigest()


def now_tag() -> str:
    return datetime.now().strftime("%Y%m%d-%H%M%S")


def save_json(path: str, data: Any) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


class CDATAClient:
    def __init__(self, host: str, timeout: int = 6, verify_tls: bool = False):
        self.host = host
        self.base_url = f"http://{host}"
        self.url = f"{self.base_url}/post.json"
        self.timeout = timeout

        self.s = requests.Session()
        self.s.headers.update({
            "User-Agent": "python-requests/2.x",
            "Accept": "*/*",
            "Content-Type": "application/json",
            "Origin": self.base_url,
            "Referer": f"{self.base_url}/",
            "Connection": "keep-alive",
        })

    def post(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        r = self.s.post(self.url, json=payload, timeout=self.timeout)
        # Algunos firmwares devuelven JSON siempre; si no, esto lo evidencia
        try:
            return r.json()
        except Exception:
            raise RuntimeError(f"Respuesta no-JSON (HTTP {r.status_code}): {r.text[:300]}")

    def login(self, username: str, password: str) -> Dict[str, Any]:
        payload = {
            "module": "login",
            "username": username,
            "encryPassword": md5_hex(password),
        }
        resp = self.post(payload)

        # Validación robusta (usted ya vio: code:0, description:"success")
        code = resp.get("code", None)
        desc = (resp.get("description") or "").lower()

        if code != 0 or "success" not in desc:
            raise RuntimeError(f"Login fallido: {resp}")

        if "session" not in self.s.cookies.get_dict():
            # Aun si el JSON dice success, debe existir cookie
            raise RuntimeError(f"Login sin cookie de sesión. Cookies: {self.s.cookies.get_dict()}")

        return resp

    def get_wan_overview(self) -> Dict[str, Any]:
        """
        Intento de lectura simple de WAN (depende del firmware).
        Si el firmware no soporta este "action", igual devolvemos la respuesta para análisis.
        """
        payload = {"module": "wan_confignew", "wan": [{"interface": ""}]}
        return self.post(payload)

    def set_bridge(self) -> Dict[str, Any]:
        """
        Aplica modo bridge. Payload basado en patrones comunes CDATA y su captura.
        Si su firmware requiere más campos (VLAN, pbit, etc.) lo extendemos.
        """
        payload = {
            "module": "wan_confignew",
            "wan": [
                {
                    "interface": "",
                    "connectionType": "bridge",
                    "natEnable": "0",
                    "serviceList": "INTERNET",
                }
            ]
        }
        return self.post(payload)

    def dev_clean_all_parts(self) -> Dict[str, Any]:
        """
        Limpieza “todo en 0” (peligrosa si se usa sin reconfigurar luego).
        Úsela solo si usted lo solicita explícitamente.
        """
  #      payload = {"module": "dev_config", "retrive_part": [0, 1, 2, 3, 4, 5, 6, 7, 8]}
        payload = {"module": "dev_config", "retrive_part": []}

        return self.post(payload)

    def reboot(self) -> Dict[str, Any]:
        payload = {"module": "system", "action": "reboot"}
        return self.post(payload)


# -------------------------
# Lógica segura Router -> Bridge
# -------------------------
def main():
    ap = argparse.ArgumentParser(description="ONU CDATA - Router -> Bridge (seguro)")
    ap.add_argument("--host", required=True, help="IP/host de la ONU (ej: 192.168.101.1)")
    ap.add_argument("--user", required=True, help="Usuario web (ej: adminisp)")
    ap.add_argument("--password", required=True, help="Password en texto plano (se hashea con MD5)")
    ap.add_argument("--outdir", default="output_onu", help="Directorio para logs/backup JSON")
    ap.add_argument("--timeout", type=int, default=6, help="Timeout HTTP en segundos")
    ap.add_argument("--dry-run", action="store_true", help="No aplica cambios, solo login y lectura/backup")
    ap.add_argument("--clean", action="store_true", help="Ejecuta dev_config (pone todo en 0) ANTES de configurar bridge")
    ap.add_argument("--reboot", action="store_true", help="Reinicia al final")
    args = ap.parse_args()

    tag = f"{args.host}_{now_tag()}"
    out = os.path.join(args.outdir, tag)

    c = CDATAClient(args.host, timeout=args.timeout)

    print(f"[+] Host: {args.host}")
    print("[+] Login...")

    login_resp = c.login(args.user, args.password)
    save_json(os.path.join(out, "01_login.json"), login_resp)

    cookies = c.s.cookies.get_dict()
    save_json(os.path.join(out, "01_cookies.json"), cookies)
    print(f"[OK] Login success. session={cookies.get('session')}")

    # 1) Snapshot (antes)
    print("[+] Snapshot WAN (antes)...")
    wan_before = c.get_wan_overview()
    save_json(os.path.join(out, "02_wan_before.json"), wan_before)

    if args.dry_run:
        print("[DRY-RUN] No se aplican cambios. Revise los JSON en:", out)
        return

    # 2) Limpieza opcional
    if args.clean:
        print("[!] Ejecutando dev_config (limpieza total)...")
        clean_resp = c.dev_clean_all_parts()
        save_json(os.path.join(out, "03_dev_config_clean.json"), clean_resp)

        # Pequeña pausa para que el equipo asiente el cambio
        time.sleep(1.0)

    # 3) Aplicar Bridge
    print("[+] Aplicando modo BRIDGE...")
    bridge_resp = c.set_bridge()
    save_json(os.path.join(out, "04_set_bridge.json"), bridge_resp)

    # 4) Verificación posterior
    print("[+] Snapshot WAN (después)...")
    wan_after = c.get_wan_overview()
    save_json(os.path.join(out, "05_wan_after.json"), wan_after)

    # 5) Evaluación de éxito (heurística)
    # Nota: como el firmware puede devolver distintas claves, guardamos todo;
    # aquí solo hacemos un chequeo simple para alertar.
    bridge_ok = False
    txt = json.dumps(bridge_resp).lower()
    if "success" in txt or bridge_resp.get("code") == 0:
        bridge_ok = True

    if bridge_ok:
        print("[OK] Configuración enviada (bridge). Revise 04_set_bridge.json / 05_wan_after.json.")
    else:
        print("[WARN] Respuesta no concluyente. Revise los JSON en:", out)

    # 6) Reboot opcional
    if args.reboot:
        print("[+] Enviando reboot...")
        reboot_resp = c.reboot()
        save_json(os.path.join(out, "06_reboot.json"), reboot_resp)
        print("[OK] Reboot enviado.")

    print("[DONE] Logs/backup en:", out)


if __name__ == "__main__":
    main()
