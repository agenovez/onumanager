#!/usr/bin/env python3
import requests
import sys
import time

# =========================
# VALIDACIÓN PARÁMETROS
# =========================

if len(sys.argv) != 4:
    print("Uso:")
    print("python3 onu_bridge_final_real.py IP_ONU NUEVA_IP_LAN VLAN_SERVICIO")
    sys.exit(1)

ONU_IP = sys.argv[1]
NEW_LAN_IP = sys.argv[2]
VLAN_SERVICE = sys.argv[3]

USER = "admin"
PASSWORD = "YnQtcG9u"

BASE = f"http://{ONU_IP}"

session = requests.Session()
session.headers.update({
    "User-Agent": "Mozilla/5.0",
    "Content-Type": "application/x-www-form-urlencoded",
    "Origin": BASE,
    "Referer": f"{BASE}/wan.html"
})

# =========================
# LOGIN
# =========================

def login():
    print("[*] Login ONU...")

    r = session.post(
        f"{BASE}/GponForm/LoginForm",
        data={
            "XWebPageName": "devinfo",
            "username": USER,
            "password": PASSWORD
        },
        timeout=6
    )

    if r.status_code != 200:
        print("[-] Error en login")
        sys.exit(1)

    print("[+] Login OK")

# =========================
# CAMBIAR LAN + DHCP OFF
# =========================

def set_lan():
    print("[*] Configurando LAN y deshabilitando DHCP...")

    payload = {
        "XWebPageName": "dhcp",
        "lanip": NEW_LAN_IP,
        "lanmask": "255.255.255.0",
        "dhcpvalue": "0",
        "leasetimesel": "2",
        "pc_enable": "1",
        "dns_relay_en": "0",
        "primary_dns": "0.0.0.0",
        "secondary_dns": "0.0.0.0"
    }

    r = session.post(
        f"{BASE}/GponForm/dhcp_Form",
        data=payload,
        timeout=6
    )

    if r.status_code != 200:
        print("[-] Error configurando LAN")
        sys.exit(1)

    print("[+] LAN actualizada y DHCP OFF")

# =========================
# VLAN 20 GESTIÓN (ROUTE)
# =========================

def configure_vlan20_mgmt():
    print("[*] Configurando VLAN 20 Gestión...")

    payload = {
        "XWebPageName": "wan",
        "wan_conlist": "2",
        "hAction": "3",
        "en_con": "on",
        "con_mode": "0",
        "wan_type": "IPTV",
        "vlan_enable": "on",
        "vlan_set": "20",
        "mvlan": "-1",
        "p802.1": "0",
        "ip_ver": "1",
        "mtu": "1500",
        "ip_mode": "1"
    }

    r = session.post(
        f"{BASE}/GponForm/wan_Form",
        data=payload,
        timeout=6
    )

    if r.status_code != 200:
        print("[-] Error configurando VLAN 20")
        sys.exit(1)

    print("[+] VLAN 20 Gestión OK")

# =========================
# BRIDGE REAL (POST EXACTO CAPTURADO)
# =========================

def configure_bridge():
    print(f"[*] Aplicando Bridge VLAN {VLAN_SERVICE}...")

    payload = {
        "XWebPageName": "wan",
        "wan_conlist": "1",
        "hAction": "3",
        "en_con": "on",
        "con_mode": "1",
        "wan_type": "IPTV",
        "vlan_enable": "on",
        "vlan_set": VLAN_SERVICE,
        "mvlan": "-1",
        "p802.1": "0",
        "lan1": "1",
        "lan2": "2",
        "ip_ver": "1",
        "mtu": "1492",
        "ip_mode": "2",
        "ipv6_addr_mode": "0",
        "ipv6_pd_mode": "2",
        "dhcpv6_ver": "0",
        "child_prefix_bits": "",
        "dslite_mode": "0",
        "pppoe_user": "",
        "pppoe_psw": "",
        "pppoe_alivetime": "",
        "dial_mode": "0",
        "servername": "",
        "dial_time": "180",
        "opt60_mode": "2",
        "static_ip": "",
        "static_mask": "",
        "static_gw": "",
        "static_pridns": "",
        "static_secdns": "",
        "static_ipv6addr": "",
        "static_ipv6addr_prefix": "",
        "static_ipv6plen": "",
        "static_ipv6gw": "",
        "static_ipv6pridns": "",
        "static_ipv6secdns": "",
        "proxy_user": "",
        "proxy_psw": "",
        "proxy_alivetime": "",
        "proxy_user_max": ""
    }

    r = session.post(
        f"{BASE}/GponForm/wan_Form",
        data=payload,
        timeout=6
    )

    if r.status_code != 200:
        print("[-] Error aplicando bridge")
        sys.exit(1)

    print("[+] Bridge aplicado correctamente")

# =========================
# REBOOT
# =========================

def reboot():
    print("[*] Reiniciando ONU...")

    session.post(
        f"{BASE}/GponForm/device_Form",
        data={
            "XWebPageName": "device",
            "admin_action": "reboot"
        },
        timeout=5
    )

    print("[+] Reboot enviado")

# =========================

def main():
    login()
    set_lan()
    configure_vlan20_mgmt()
    configure_bridge()
    time.sleep(2)
    reboot()

    print("\n=======================================")
    print("✅ ONU PROVISIONADA CORRECTAMENTE")
    print("➡ VLAN 20 Gestión activa")
    print("➡ WAN Servicio en BRIDGE")
    print("➡ Conectar router en LAN1")
    print("=======================================")

if __name__ == "__main__":
    main()
