#!/usr/bin/env python3

import subprocess
import xml.etree.ElementTree as ET
import os
from rich.console import Console
from rich.table import Table

console = Console()

# -------------------- BANNER --------------------
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
[cyan]Pentra - Pentest Ultra Framework[/cyan]
[white]Created by @Zeref0xD[/white]
""")

# -------------------- INPUT --------------------
def get_target():
    console.print("\nEnter Target IP:")
    return input("> ")

def get_output_format():
    console.print("""
Select Output Format:

1. XML
2. TXT
3. GNMAP
4. ALL
""")
    return input("> ")

# -------------------- PING --------------------
def check_host_alive(target):
    result = subprocess.getoutput(f"ping -c 3 {target}")
    return "bytes from" in result

# -------------------- NMAP --------------------
def run_nmap(target, use_pn, fmt):
    console.print("\n[*] Running Scan Engine...")

    cmd = ["nmap", "-p-", "-sC", "-sV", "-O"]

    if use_pn:
        cmd.append("-Pn")

    if fmt == "1":
        cmd += ["-oX", "pentra_scan.xml"]
    elif fmt == "2":
        cmd += ["-oN", "pentra_scan.txt"]
    elif fmt == "3":
        cmd += ["-oG", "pentra_scan.gnmap"]
    elif fmt == "4":
        cmd += ["-oX", "pentra_scan.xml", "-oN", "pentra_scan.txt", "-oG", "pentra_scan.gnmap"]

    cmd.append(target)

    subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    console.print("[+] Scan Completed")

# -------------------- PARSE --------------------
def parse_xml():
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

# -------------------- DISPLAY --------------------
def show_ports(ports):
    table = Table(title="Open Ports")

    table.add_column("Port")
    table.add_column("Service")
    table.add_column("Version")

    for p in ports:
        table.add_row(p["port"], p["service"], p["product"] + " " + p["version"])

    console.print(table)

# -------------------- ANALYSIS --------------------
def analyze(ports):
    seen = set()
    console.print("\n[bold red]Priority Findings:[/bold red]")

    for p in ports:
        s = p["service"].lower()
        v = p["version"].lower()

        if "tomcat" in v and "tomcat" not in seen:
            console.print("[HIGH] Tomcat detected")
            seen.add("tomcat")

        elif ("smb" in s or "netbios" in s) and "smb" not in seen:
            console.print("[HIGH] SMB detected")
            seen.add("smb")

        elif "http" in s and "http" not in seen:
            console.print("[MED] Web service detected")
            seen.add("http")

# -------------------- CVE --------------------
def search_cve(version):
    try:
        result = subprocess.check_output(
            f"searchsploit '{version}'",
            shell=True
        ).decode(errors="ignore")

        if "No Results" not in result:
            console.print("[red][!] Possible exploit found[/red]")
    except:
        pass

# -------------------- SERVICE INTEL --------------------
def deep_service_output(service, target):
    service = service.lower()

    console.print("[green]What to look for:[/green]")

    if "ssh" in service:
        console.print("- Weak credentials")
        console.print("- Private keys (id_rsa)")
        console.print("- Password reuse")

        console.print("\n[cyan]Commands:[/cyan]")
        console.print(f"ssh user@{target}")
        console.print(f"hydra -l root -P rockyou.txt ssh://{target}")
        console.print(f"nxc ssh {target}")

    elif "http" in service:
        console.print("- Login panels (/admin, /login)")
        console.print("- File upload vulnerabilities")
        console.print("- Hidden directories")

        console.print("\n[cyan]Commands:[/cyan]")
        console.print(f"ffuf -u http://{target}/FUZZ -w wordlist")
        console.print(f"feroxbuster -u http://{target}")
        console.print(f"gobuster dir -u http://{target}")

    elif "smb" in service or "netbios" in service:
        console.print("- Anonymous login")
        console.print("- Shared files")
        console.print("- Credentials exposure")

        console.print("\n[cyan]Commands:[/cyan]")
        console.print(f"smbclient -L //{target} -N")
        console.print(f"enum4linux {target}")
        console.print(f"nxc smb {target}")

    else:
        console.print("- Unknown service, investigate manually")

        console.print("\n[cyan]Commands:[/cyan]")
        console.print(f"nmap -sC -sV -p <port> {target}")
        console.print(f"searchsploit {service}")

# -------------------- MAIN --------------------
def main():
    banner()

    target = get_target()
    fmt = get_output_format()

    alive = check_host_alive(target)

    if not alive:
        console.print("[yellow][!] Ping blocked → using -Pn[/yellow]")

    run_nmap(target, not alive, fmt)

    ports = parse_xml()

    show_ports(ports)
    analyze(ports)

    console.print("\n[bold magenta]Deep Analysis[/bold magenta]")

    for p in ports:
        service = p["service"]
        version = p["product"] + " " + p["version"]

        console.print(f"\n[bold cyan]--- {service.upper()} ({p['port']}) ---[/bold cyan]")

        search_cve(version)
        deep_service_output(service, target)

    console.print("\n[bold green]✔ Pentra Complete[/bold green]")

if __name__ == "__main__":
    main()
