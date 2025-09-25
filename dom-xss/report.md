# DOM-Based Cross-Site Scripting (XSS) – Vulnerability Report

## Summary
A DOM-Based XSS vulnerability was discovered in DVWA where client-side JavaScript takes untrusted input from the URL query string and injects it into the DOM using `innerHTML` without sanitization. This allows malicious scripts to be executed in the browser of any visitor who follows a crafted URL.

## Affected Module
DVWA → XSS (DOM)

## Reproduction Steps
1. Navigate to:
http://localhost:8080/DVWA/vulnerabilities/xss_d/
2. Set DVWA Security Level to Low
3. Modify the URL to:
```html
http://localhost:8080/DVWA/vulnerabilities/xss_d/?default=<script>alert('DOM XSS')</script>
```

4. Press Enter

Result: A JavaScript alert is triggered, confirming execution of injected code.

## Additional Payloads Tested

Cookie access:

```html
<script>alert(document.cookie)</script>
Image-based XSS:
```

```html
<img src=x onerror=alert('Image XSS')>
```

## Impact

- Script execution in the victim’s browser

- Theft of session cookies or browser data

- Full control of DOM from attacker-crafted links

- High risk in single-page apps (SPAs) and dynamic frontends

## Recommendations
Never inject untrusted input using innerHTML

Use .textContent or .innerText for safe DOM manipulation

Sanitize input using libraries like DOMPurify

Apply a Content Security Policy (CSP) to reduce script execution risk


