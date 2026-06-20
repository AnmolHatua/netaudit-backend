import subprocess
import xml.etree.ElementTree as ET
import re

def perform_scan(target: str, scan_type: str = "fast") -> dict:
    if scan_type == "detailed":
        args = ["nmap", "-sT", "-Pn", "-sV", "-p", "1-1000", "-T4", "--max-retries", "1", "--host-timeout", "150s"]
    else:
        args = ["nmap", "-sT", "-Pn", "-F", "-sV", "--version-light", "-T4", "--max-retries", "1"]

    args += ["-oX", "-", target]

    try:
        result = subprocess.run(args, capture_output=True, text=True, timeout=180)
    except subprocess.TimeoutExpired:
        raise Exception("Nmap scan timed out after 180 seconds")

    if result.returncode != 0:
        raise Exception(f"Nmap failed (code {result.returncode}): {result.stderr[:500]}")

    return _parse_nmap_xml(result.stdout)


def _parse_nmap_xml(xml_str: str) -> dict:
    results = {}
    try:
        root = ET.fromstring(xml_str)
    except ET.ParseError as e:
        raise Exception(f"Failed to parse Nmap XML output: {e}")

    for host in root.findall("host"):
        status = host.find("status")
        if status is None:
            continue
        host_state = status.get("state", "unknown")

        addr = host.find("address")
        if addr is None:
            continue
        host_ip = addr.get("addr", "unknown")

        hostnames_el = host.find("hostnames")
        hostname_str = ""
        if hostnames_el is not None:
            h = hostnames_el.find("hostname")
            if h is not None:
                hostname_str = h.get("name", "")

        host_info = {
            "state": host_state,
            "hostnames": hostname_str,
            "protocols": {},
        }

        for ports_el in host.findall("ports"):
            for port_el in ports_el.findall("port"):
                proto = port_el.get("protocol", "tcp")
                port_id = port_el.get("portid", "0")

                state_el = port_el.find("state")
                port_state = state_el.get("state", "unknown") if state_el is not None else "unknown"

                service_el = port_el.find("service")
                name = service_el.get("name", "") if service_el is not None else ""
                product = service_el.get("product", "") if service_el is not None else ""
                version = service_el.get("version", "") if service_el is not None else ""
                extrainfo = service_el.get("extrainfo", "") if service_el is not None else ""
                cpe = ""
                if service_el is not None:
                    cpe_el = service_el.find("cpe")
                    if cpe_el is not None:
                        cpe = cpe_el.text or ""

                scripts = {}
                for script_el in port_el.findall("script"):
                    scripts[script_el.get("id", "")] = script_el.get("output", "")

                if proto not in host_info["protocols"]:
                    host_info["protocols"][proto] = {}

                host_info["protocols"][proto][port_id] = {
                    "state": port_state,
                    "name": name,
                    "product": product,
                    "version": version,
                    "extrainfo": extrainfo,
                    "cpe": cpe,
                    "vulnerabilities": scripts,
                }

        results[host_ip] = host_info

    return results
