import nmap

def perform_scan(target: str, scan_type: str = "fast") -> dict:
    """
    Executes an Nmap scan on the target and parses the output.
    """
    nm = nmap.PortScanner()
    
    # Define arguments based on scan_type
    # -sV: Probe open ports to determine service/version info
    # -F: Fast mode - Scan fewer ports than the default scan
    # --script vuln: Run all built-in vulnerability detection scripts
    # -T4: Aggressive timing to speed up scans
    # --max-retries 1: Don't hang on dropped packets
    # --script-timeout: Stop slow scripts
    if scan_type == "detailed":
        # Deep scan: Uses vulnerability scripts and full version detection
        # -sT: TCP connect scan (works in containers without CAP_NET_RAW)
        # -Pn: Skip host discovery (assume host is up, handles no-ICMP environments)
        nmap_args = "-sT -Pn -sV --script vuln -p 1-1000 -T4 --max-retries 1 --script-timeout 2m"
    else:
        # Fast mode: Only top 100 ports (-F), fast version detection, no vuln scripts for speed
        nmap_args = "-sT -Pn -F -sV --version-light -T4 --max-retries 1"
        
    try:
        nm.scan(hosts=target, arguments=nmap_args)
    except nmap.PortScannerError as e:
        raise Exception(f"Nmap scan error: {e}")
    except Exception as e:
        raise Exception(f"Unexpected error during Nmap scan: {e}")

    # Parse results into a structured dictionary
    results = {}
    
    for host in nm.all_hosts():
        host_info = {
            "state": nm[host].state(),
            "hostnames": nm[host].hostname(),
            "protocols": {}
        }
        
        for proto in nm[host].all_protocols():
            ports = nm[host][proto].keys()
            port_info = {}
            for port in sorted(ports):
                port_data = nm[host][proto][port]
                port_info[port] = {
                    "state": port_data["state"],
                    "name": port_data["name"],
                    "product": port_data.get("product", ""),
                    "version": port_data.get("version", ""),
                    "extrainfo": port_data.get("extrainfo", ""),
                    "cpe": port_data.get("cpe", ""),
                    "vulnerabilities": port_data.get("script", {})
                }
            host_info["protocols"][proto] = port_info
            
        results[host] = host_info

    return results
