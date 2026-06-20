import os
import json
from groq import Groq

# Initialize Groq client
# Assumes GROQ_API_KEY is set in the environment
client = Groq(
    api_key=os.environ.get("GROQ_API_KEY"),
)

def format_scan_data_for_prompt(scan_data: dict) -> str:
    """
    Minimizes the Nmap output to save tokens before sending to the LLM.
    Extracts only open ports, services, versions, and confirmed vulnerabilities from NSE scripts.
    """
    simplified_data = {}
    for host, host_info in scan_data.items():
        if host_info.get("state") != "up":
            continue
            
        simplified_data[host] = []
        for proto, ports in host_info.get("protocols", {}).items():
            for port, port_data in ports.items():
                if port_data.get("state") == "open":
                    service = port_data.get("name", "unknown")
                    product = port_data.get("product", "")
                    version = port_data.get("version", "")
                    vulns = port_data.get("vulnerabilities", {})
                    
                    details = f"{proto}/{port}: {service}"
                    if product or version:
                        details += f" ({product} {version})"
                    
                    if vulns:
                        # Append any NSE script vulnerability outputs (e.g., vulners, smb-vuln-ms17-010)
                        details += f" | Known Vulnerabilities Detected by Nmap: {json.dumps(vulns)}"
                        
                    simplified_data[host].append(details)
                    
    return simplified_data

def generate_remediation_plan(scan_data: dict, http_analysis: dict, scan_type: str = "fast") -> list:
    """
    VIVA-PROOF EXPLANATION:
    Sends the parsed Nmap data AND HTTP Header Analysis to Groq to identify potential CVEs
    and generate actionable remediation steps. We pass both data sources to the LLM
    so it can synthesize a comprehensive security report.
    """
    formatted_data = format_scan_data_for_prompt(scan_data)
    
    # If no open ports were found and no HTTP issues, return early
    if not any(formatted_data.values()) and not http_analysis:
         return [{"issue": "No vulnerabilities detected", "remediation": "No action required. Host appears secure from external scans.", "severity": "Info"}]

    if scan_type == "detailed":
        system_prompt = """
        You are an expert Cybersecurity Engineer. Analyze the provided Nmap scan results AND HTTP Security Header analysis.
        
        CRITICAL RULES (DEEP SCAN):
        1. Provide CRISP, accurate, and highly detailed technical analysis without unnecessary fluff.
        2. Keep token limits strictly in check. Do not write essays. Use extremely concise, exact configuration snippets (e.g., a few lines of Nginx/Apache config or iptables commands).
        3. Standard web ports (80, 443) are EXPECTED to be open. Do NOT flag them as vulnerabilities UNLESS they lack security headers or run heavily outdated software.
        4. Focus Critical/High alerts on risky exposed services (FTP, Telnet, exposed databases, outdated SSH).
        
        You MUST respond with a valid JSON object containing exactly ONE key named "remediations". 
        The value of "remediations" must be an array of objects. Each object in the array MUST have EXACTLY these keys:
        - "issue": A precise, technical title of the vulnerability.
        - "severity": The severity level (Critical, High, Medium, Low, Info).
        - "cves": An array of known CVEs (e.g., ["CVE-2023-1234"]) or [] if none.
        - "remediation": Crisp, step-by-step technical mitigation instructions with short, exact config snippets.
        - "affected_services": A string listing the relevant port(s), protocol, and service.
        """
    else:
        system_prompt = """
        You are a friendly Cybersecurity Educator. Analyze the provided Nmap scan results AND HTTP Security Header analysis.
        
        CRITICAL RULES (FAST SCAN):
        1. Keep it EXTREMELY short and beginner-friendly. A first-time viewer must understand the issue immediately.
        2. Strictly limit token usage. Explain the issue and the fix in just 1 to 3 simple sentences.
        3. DO NOT output long configuration scripts or code. Explain the concept of the fix simply (e.g., "Enable HTTPS to encrypt traffic" or "Close this port using a firewall").
        4. Web ports are expected to be open. Only flag them if they lack headers or run old software.
        
        You MUST respond with a valid JSON object containing exactly ONE key named "remediations". 
        The value of "remediations" must be an array of objects. Each object in the array MUST have EXACTLY these keys:
        - "issue": A simple, easy-to-understand description of the vulnerability.
        - "severity": The severity level (Critical, High, Medium, Low, Info).
        - "cves": An array of known CVEs or [] if none.
        - "remediation": A very short, beginner-friendly explanation of how to fix it (maximum 3 sentences, no code blocks).
        - "affected_services": The affected port/service.
        """
    
    try:
        response = client.chat.completions.create(
            messages=[
                {
                    "role": "system",
                    "content": system_prompt,
                },
                {
                    "role": "user",
                    "content": f"Nmap Scan Data:\n{json.dumps(formatted_data, indent=2)}\n\nHTTP Header Analysis:\n{json.dumps(http_analysis, indent=2)}",
                }
            ],
            model="llama-3.1-8b-instant", # Fast and capable model
            temperature=0.2, # Low temperature for more deterministic/factual output
            response_format={"type": "json_object"}
        )
        
        content = response.choices[0].message.content
        
        # Parse the JSON response
        try:
            parsed = json.loads(content)
            if isinstance(parsed, dict) and "remediations" in parsed:
                return parsed["remediations"]
            if isinstance(parsed, list):
                return parsed
            
            return [{"issue": "AI parsed data incorrectly", "remediation": f"Raw output: {content}", "severity": "Info"}]
        except json.JSONDecodeError:
             return [{"issue": "Failed to parse AI response", "remediation": f"Raw output: {content}", "severity": "Info"}]
             
    except Exception as e:
        print(f"Error calling Groq API: {e}")
        return [{"issue": "AI Analysis Failed", "remediation": str(e), "severity": "Error"}]
