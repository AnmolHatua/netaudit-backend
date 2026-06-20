import os
import re
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

import requests
import urllib3
from scanner import perform_scan
from ai_agent import generate_remediation_plan

# Disable insecure request warnings when checking HTTPS without proper certs
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = FastAPI(
    title="NetAudit AI API",
    description="API for the AI-Assisted Vulnerability Mapper",
    version="1.0.0"
)

# Setup Rate Limiter
limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# CORS config to allow the specified frontend(s)
FRONTEND_URLS = os.environ.get("FRONTEND_URLS", "http://localhost:3000")
ALLOWED_ORIGINS = [url.strip() for url in FRONTEND_URLS.split(",") if url.strip()]
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Regex to validate safe hostnames, IPv4, IPv6, and CIDR blocks
# Prevents shell injection (e.g. example.com; rm -rf /)
TARGET_REGEX = re.compile(r"^([a-zA-Z0-9.-]+|\[[a-fA-F0-9:]+\])(/\d{1,2})?$")

# Define the data structure for incoming scan requests
class ScanRequest(BaseModel):
    target: str # Accepts IP, subnet (e.g. 192.168.1.0/24), or hostname
    scan_type: Optional[str] = "fast" # Options: fast, detailed

# Define the data structure for the outgoing scan response
class ScanResponse(BaseModel):
    target: str
    status: str
    scan_results: dict
    http_headers: dict # Added to hold our HTTP Security Header analysis
    remediation_plan: list

def analyze_http_headers(target: str, ports: list) -> dict:
    """
    VIVA-PROOF EXPLANATION:
    This function analyzes the HTTP security headers of a given target. 
    It checks if port 80 (HTTP) or 443 (HTTPS) is open. If they are, it uses the 
    Python 'requests' library to send a GET request and retrieve the server's response headers.
    It then compares the retrieved headers against a list of recommended security headers
    (like Strict-Transport-Security or Content-Security-Policy) to identify misconfigurations.
    """
    results = {}
    
    # We check both HTTP (80) and HTTPS (443) if they were detected by Nmap
    for port in ports:
        if port not in [80, 443, 8080, 8443]:
            continue
            
        protocol = "https" if port in [443, 8443] else "http"
        url = f"{protocol}://{target}:{port}"
        
        try:
            # We use verify=False because the target might use self-signed certificates
            response = requests.get(url, timeout=5, verify=False, allow_redirects=False)
            headers = {k.lower(): v for k, v in response.headers.items()}
            
            # Key security headers we want to look for
            security_headers = {
                "strict-transport-security": "Missing HSTS - Leaves site vulnerable to downgrade attacks.",
                "content-security-policy": "Missing CSP - Increases risk of Cross-Site Scripting (XSS).",
                "x-frame-options": "Missing X-Frame-Options - Vulnerable to Clickjacking.",
                "x-content-type-options": "Missing X-Content-Type-Options - Vulnerable to MIME sniffing."
            }
            
            missing_headers = []
            for header, risk in security_headers.items():
                if header not in headers:
                    missing_headers.append(risk)
                    
            results[f"{protocol}/{port}"] = {
                "status_code": response.status_code,
                "server": headers.get("server", "Unknown"),
                "missing_headers": missing_headers
            }
            
        except requests.RequestException as e:
            results[f"{protocol}/{port}"] = {"error": f"Failed to connect: {str(e)}"}
            
    return results

@app.post("/api/v1/scan", response_model=ScanResponse)
@limiter.limit("5/minute")
async def run_scan(request: Request, scan_request: ScanRequest):
    from urllib.parse import urlparse
    raw_target = scan_request.target.strip()
    
    if "://" in raw_target:
        # urlparse handles stripping http://, ports, and paths automatically
        clean_target = urlparse(raw_target).hostname or raw_target
    else:
        # Check if user pasted domain:port without http:// (avoiding IPv6 destruction)
        if ":" in raw_target and raw_target.count(":") == 1:
            clean_target = raw_target.split(":")[0]
        # Handle trailing slashes or paths, making sure NOT to break CIDR blocks
        elif "/" in raw_target:
            parts = raw_target.split("/")
            if len(parts) == 2 and parts[1].isdigit() and 1 <= int(parts[1]) <= 32:
                clean_target = raw_target # It's a valid CIDR
            else:
                clean_target = parts[0] # It's a domain with a path
        else:
            clean_target = raw_target

    # Security: Strict Regex Validation
    if not TARGET_REGEX.match(clean_target):
        raise HTTPException(status_code=400, detail="Invalid target format. Only valid hostnames, IPs, or CIDR blocks are allowed.")

    try:
        # ---------------------------------------------------------
        # 1. Execute Nmap Scan
        # VIVA-PROOF: We pass the sanitized target to our scanner module, 
        # which runs OS-level nmap commands to discover open ports and services.
        # ---------------------------------------------------------
        print(f"Starting scan on target: {clean_target}")
        scan_data = perform_scan(clean_target, scan_request.scan_type)
        
        if not scan_data:
            return ScanResponse(
                target=clean_target,
                status="failed",
                scan_results={},
                http_headers={},
                remediation_plan=[{"issue": "No hosts found", "remediation": "Check if the target is online and reachable.", "severity": "Info"}]
            )

        # ---------------------------------------------------------
        # 2. Extract Open Web Ports for HTTP Header Analysis
        # VIVA-PROOF: We parse the raw Nmap JSON to find if any web ports 
        # are open. If so, we call our HTTP header analyzer.
        # ---------------------------------------------------------
        print("Checking for web ports to analyze HTTP Security Headers...")
        web_ports = []
        for host, host_info in scan_data.items():
            for proto, ports in host_info.get("protocols", {}).items():
                for port, port_data in ports.items():
                    if port_data.get("state") == "open":
                        web_ports.append(port)
        
        http_analysis = analyze_http_headers(clean_target, web_ports)

        # ---------------------------------------------------------
        # 3. Analyze with Groq AI
        # VIVA-PROOF: We send both the Nmap raw data AND the HTTP header 
        # analysis to the LLM. The AI reads this context and outputs a 
        # prioritized JSON array of mitigation steps.
        # ---------------------------------------------------------
        print("Analyzing scan results with Groq AI...")
        remediation_steps = generate_remediation_plan(scan_data, http_analysis, scan_request.scan_type)
        
        return ScanResponse(
            target=clean_target,
            status="success",
            scan_results=scan_data,
            http_headers=http_analysis,
            remediation_plan=remediation_steps
        )
    except Exception as e:
        print(f"Error during scan: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/v1/health")
async def health_check():
    return {"status": "healthy"}


@app.get("/api/v1/debug")
async def debug():
    return {"message": "debug endpoint placeholder"}

