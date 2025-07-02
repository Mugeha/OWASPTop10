# Vulnerable and Outdated Components – Vulnerability Report

## Summary

The application under review (DVWA) uses outdated software components across its stack, including the PHP runtime, Apache server, and JavaScript libraries. These components have known vulnerabilities (CVEs) that attackers can exploit for code execution, data leakage, or server takeover.

## Affected System

DVWA (Damn Vulnerable Web Application) running on local Apache server in WSL

## Reproduction & Findings

### 1. Outdated PHP Version

- **Observed**: PHP/7.4.3
- **Reference**: End-of-Life (EOL) since Nov 2022
- **Risk**: Vulnerable to multiple CVEs including:
  - Remote Code Execution (RCE)
  - Heap overflow vulnerabilities

### 2. Outdated Apache Version

- **Observed**: Apache/2.4.41
- **Risk**: Includes vulnerabilities like:
  - HTTP/2 DoS (CVE-2020-11993)
  - Path traversal and server exposure flaws

### 3. jQuery 1.9.1 Detected

- **Observed in DVWA Source**: 
  ```html
  <script src="js/jquery-1.9.1.min.js"></script>
**Released: 2013**

**Risk**:

Known vulnerabilities including:

- XSS

 - DOM injection

- Selector bypass

### 4. Leaky headers

Via network tab
```bash
Server: Apache/2.4.41 (Ubuntu)
X-Powered-By: PHP/7.4.3
```
**Risk**: Allows attackers to fingerprint stack and craft specific exploits

### 5. Misconfigured File Exposure

**Tested**:

 - composer.lock, vendor/, info.php

 - Simulated real-world leakage, though not present in DVWA

**Risk**: In real apps, these could reveal package versions and structure

## Recommendations

 - Upgrade PHP to actively supported version (8.2+)

 - Patch Apache to latest stable version

 - Replace jQuery 1.9.1 with v3.x or newer

 - Strip version information from response headers (Apache config)

 - Remove or block access to internal configuration files and directories

 - Use automated dependency scanners like:

    - npm audit

    - composer audit

    - pip-audit

    - Dependabot/GitHub Security Alerts


## Notes

While DVWA is intentionally insecure, these issues mirror real-world app deployments where patching is neglected and legacy components are left in place.