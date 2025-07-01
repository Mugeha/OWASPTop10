# Security Misconfiguration – Vulnerability Report

## Summary
Security misconfiguration vulnerabilities were identified in the DVWA lab environment. These flaws are common in real-world systems and can lead to unauthorized access, information leakage, or complete system compromise. Each discovery demonstrates poor configuration practices that must be corrected in production systems.

## Affected System
DVWA running locally on Apache and MySQL via WSL

## Reproduction & Findings

### 1. Exposed `phpinfo.php`
- **URL**: http://localhost:8080/DVWA/phpinfo.php
- **Impact**: Reveals PHP version, server paths, and environment variables.
- **Risk**: Attackers can tailor exploits based on software versions or file locations.

### 2. Accessible `.git/` Folder
- **URL**: http://localhost:8080/.git/
- **Impact**: Potential to download full codebase and inspect version history.
- **Risk**: May expose hardcoded credentials, internal APIs, and sensitive business logic.

### 3. Default Credentials
- **Login**: `admin:password`
- **Impact**: Immediate access to protected admin features.
- **Risk**: Enables brute-force attacks or privilege escalation.

### 4. Error Disclosure
- **Test**: Navigating to vulnerable modules with bad input
- **Observation**: Errors did not leak sensitive data in this case, but behavior varies based on settings.
- **Risk**: Detailed stack traces could aid attackers.

### 5. Directory Listing
- **Test URL**: http://localhost:8080/uploads/
- **Observation**: Directory listing was not allowed — secure behavior.
- **Risk (if enabled)**: Exposes user-uploaded files or configuration dumps.

## Recommendations
- Remove or restrict access to `phpinfo.php` in production
- Prevent `.git/` and other hidden folders from being publicly accessible
- Enforce password change at first login; disable default accounts
- Disable directory browsing on the server
- Apply the principle of least privilege to services and file permissions
- Monitor and restrict file extensions that can be uploaded to public directories

## Notes
Though the lab ran locally, similar misconfigurations in public-facing apps could result in severe compromise. Proper DevSecOps hygiene and configuration audits are essential.

