# Identification and Authentication Failures – Vulnerability Report

## Summary
The DVWA application demonstrates multiple authentication-related weaknesses that expose it to unauthorized access, credential brute-forcing, and session hijacking. These vulnerabilities are common in poorly secured applications and critical for attackers attempting to impersonate or escalate privileges.

## Affected System
DVWA running on Apache in WSL

## Reproduction & Findings

### 1. User Enumeration
- **Test**: Tried valid and invalid usernames on the login form.
- **Result**: Error messages differed, allowing attackers to identify valid usernames.
- **Impact**: Enables targeted brute-force and phishing attacks.

### 2. Brute-Force Vulnerability
- **Test**: Repeated login attempts using common passwords for `admin`
- **Result**: No rate-limiting, account lockout, or CAPTCHA
- **Impact**: Automated password guessing is possible using tools or scripts

### 3. Weak Default Credentials
- **Test**: Logged in with `admin:password`
- **Result**: Successful login
- **Impact**: Systems using default or weak credentials are easily compromised

### 4. Predictable Session IDs
- **Observation**: Session ID is a short `PHPSESSID` token stored in cookies
- **Impact**: Can be guessed or reused if not rotated or invalidated securely

### 5. Session Fixation
- **Test**: Reused an old session ID after logout
- **Result**: Able to regain access without logging in again
- **Impact**: Attacker can set or reuse a victim’s session ID to gain access

## Recommendations
- Use consistent error messages for login attempts (e.g., “Invalid credentials”)
- Enforce strong password policies; disable default credentials
- Add rate-limiting, account lockouts, and CAPTCHA to login forms
- Use secure, long, randomized session tokens (e.g., UUID v4)
- Rotate session IDs after login; destroy them on logout
- Enable secure cookie flags (`HttpOnly`, `Secure`, `SameSite`)

## Notes
While DVWA is intentionally insecure for educational use, these same vulnerabilities have led to real-world breaches and account takeovers.
