# Server-Side Request Forgery (SSRF) – Vulnerability Report

## Summary
The DVWA environment was tested for SSRF behavior through its File Inclusion module. Although DVWA does not have a dedicated SSRF section, we simulated SSRF using local and remote file/resource loading. The system demonstrated SSRF-like behavior when fetching internal files and partially rendering remote server requests.

## Affected System
DVWA running in Apache (WSL Ubuntu)

## Reproduction & Findings

### 1. Local File Inclusion of `/etc/passwd`
- **Tested URL**: 
http://localhost:8080/DVWA/vulnerabilities/fi/?page=/etc/passwd

- **Result**: System returned the contents of `/etc/passwd`, confirming Local File Inclusion (LFI)
- **Impact**: Attacker can read internal OS files and enumerate user accounts

### 2. HTTP Request to `127.0.0.1`
- **Tested URL**:
http://localhost:8080/DVWA/vulnerabilities/fi/?page=http://127.0.0.1/
- **Result**: No main content was displayed, but the sidebar and vulnerability list loaded
- **Impact**: Confirms partial SSRF behavior — server processed a localhost HTTP request, exposing internal service structure

## Observations
- The application allows unsanitized inclusion of remote and local resources
- `allow_url_include` was enabled to simulate RFI (Remote File Inclusion) and SSRF behavior
- Although metadata endpoints like `169.254.169.254` couldn't be tested locally, DVWA shows how vulnerable file loading can lead to SSRF-like attacks

## Recommendations
- Disable `allow_url_include` in production environments
- Whitelist allowed files or resources when including user input in file paths
- Block internal IPs (127.0.0.1, 169.254.169.254, etc.) from external HTTP requests
- Use metadata filtering libraries or SSRF protection middleware
- Monitor and alert on suspicious internal HTTP traffic

## Notes
Though DVWA is designed for vulnerability demonstration, similar SSRF vulnerabilities in production applications have led to major breaches like the Capital One AWS compromise.
