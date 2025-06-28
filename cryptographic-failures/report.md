# Cryptographic Failures – Vulnerability Report

## Summary
Sensitive login credentials were transmitted over an unencrypted HTTP connection in DVWA. This vulnerability enables interception of data via man-in-the-middle (MitM) attacks, exposing users' passwords and session tokens.

## Affected Module
DVWA Login page over HTTP

## Reproduction Steps
1. Open DVWA at `http://localhost:8080`
2. Use Burp Suite to intercept login traffic
3. Observe credentials sent in plaintext through POST

## Evidence
- Intercepted POST request contains username and password in plain text

## Impact
- Credential theft
- Session hijacking
- Complete account compromise

## Recommendations
- Enforce HTTPS for all sensitive interactions
- Use HSTS headers to block HTTP fallback
- Avoid transmitting secrets in cleartext
