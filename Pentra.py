#!/usr/bin/env python3

import subprocess
import xml.etree.ElementTree as ET
import os
from rich.console import Console
from rich.table import Table

console = Console()

def banner():
    console.print("""
[bold red]
██████╗ ███████╗███╗   ██╗████████╗██████╗  █████╗ 
██╔══██╗██╔════╝████╗  ██║╚══██╔══╝██╔══██╗██╔══██╗
██████╔╝█████╗  ██╔██╗ ██║   ██║   ██████╔╝███████║
██╔═══╝ ██╔══╝  ██║╚██╗██║   ██║   ██╔══██╗██╔══██║
██║     ███████╗██║ ╚████║   ██║   ██║  ██║██║  ██║
╚═╝     ╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝
[/bold red]
Pentra - Pentest Ultra Framework
Created by @Zeref0xD
""")

def get_target():
    console.print("\nEnter Target IP:")
    return input("> ")

def get_format():
    console.print("""
Select Output Format:

1. XML
2. TXT
3. GNMAP
4. ALL
""")
    return input("> ")

def check_host(target):
    r = subprocess.getoutput(f"ping -c 3 {target}")
    return "bytes from" in r

def run_scan(target, use_pn, fmt):
    cmd = ["nmap", "-p-", "-sC", "-sV", "-O", "-oX", "pentra_scan.xml"]

    if use_pn:
        cmd.append("-Pn")

    if fmt == "2":
        cmd += ["-oN", "pentra_scan.txt"]
    elif fmt == "3":
        cmd += ["-oG", "pentra_scan.gnmap"]
    elif fmt == "4":
        cmd += ["-oN", "pentra_scan.txt", "-oG", "pentra_scan.gnmap"]

    cmd.append(target)

    subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def parse():
    ports = []

    if not os.path.exists("pentra_scan.xml"):
        return ports

    tree = ET.parse("pentra_scan.xml")
    root = tree.getroot()

    for port in root.iter("port"):
        if port.find("state").attrib["state"] == "open":
            service = port.find("service")
            ports.append({
                "port": port.attrib["portid"],
                "service": service.attrib.get("name", ""),
                "product": service.attrib.get("product", ""),
                "version": service.attrib.get("version", "")
            })

    return ports

def show_ports(ports):
    table = Table(title="Open Ports")
    table.add_column("Port")
    table.add_column("Service")
    table.add_column("Version")

    for p in ports:
        table.add_row(p["port"], p["service"], (p["product"] + " " + p["version"]).strip())

    console.print(table)

def analyze(ports):
    seen = set()
    console.print("\nPriority Findings:\n")

    for p in ports:
        s = p["service"].lower()
        v = (p["product"] + " " + p["version"]).lower()

        if ("ldap" in s or "kerberos" in s) and "ad" not in seen:
            console.print("[HIGH] Active Directory detected")
            seen.add("ad")

        elif ("smb" in s or "netbios" in s) and "smb" not in seen:
            console.print("[HIGH] SMB detected")
            seen.add("smb")

        elif "http" in s and "http" not in seen:
            console.print("[MED] Web service detected")
            seen.add("http")

        elif "ssh" in s and "ssh" not in seen:
            console.print("[LOW] SSH detected")
            seen.add("ssh")

def cve(version):
    try:
        r = subprocess.check_output(f"searchsploit '{version}'", shell=True, stderr=subprocess.DEVNULL).decode(errors="ignore")
        if "No Results" not in r:
            console.print("[!] Possible exploit available")
    except:
        pass

def intel(service, target):
    s = service.lower()

    console.print("What to look for:")

    if "http" in s:
        console.print("- Login panels")
        console.print("- File upload")
        console.print("- Hidden directories")
        console.print("\nCommands:")
        console.print(f"ffuf -u http://{target}/FUZZ -w wordlist")
        console.print(f"feroxbuster -u http://{target}")
        console.print(f"gobuster dir -u http://{target}")

    elif "ssh" in s:
        console.print("- Weak credentials")
        console.print("- Key-based access")
        console.print("\nCommands:")
        console.print(f"ssh user@{target}")
        console.print(f"hydra -l root -P rockyou.txt ssh://{target}")
        console.print(f"nxc ssh {target}")

    elif "smb" in s or "netbios" in s:
        console.print("- Anonymous access")
        console.print("- Shared files")
        console.print("\nCommands:")
        console.print(f"smbclient -L //{target} -N")
        console.print(f"enum4linux {target}")
        console.print(f"nxc smb {target}")

    elif "ldap" in s or "kerberos" in s:
        console.print("- Domain users")
        console.print("- Kerberoasting")
        console.print("- AS-REP roasting")
        console.print("\nCommands:")
        console.print(f"nxc ldap {target}")
        console.print(f"nxc smb {target}")

    else:
        console.print("- Manual investigation required")
        console.print("\nCommands:")
        console.print(f"nmap -sC -sV -p <port> {target}")
        console.print(f"searchsploit {service}")

def main():
    banner()

    target = get_target()
    fmt = get_format()

    alive = check_host(target)

    run_scan(target, not alive, fmt)

    ports = parse()

    show_ports(ports)
    analyze(ports)

    console.print("\nDeep Analysis\n")

    for p in ports:
        console.print(f"{p['service']} ({p['port']})")
        cve(p["product"] + " " + p["version"])
        intel(p["service"], target)
        console.print("")

    console.print("Pentra Complete")

if __name__ == "__main__":
    main()
