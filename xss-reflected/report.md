# Reflected Cross-Site Scripting (XSS) – Vulnerability Report

## Summary
A reflected XSS vulnerability was found in DVWA where user input is echoed into the HTML response without sanitization. This allows arbitrary JavaScript execution in a victim’s browser.

## Affected Module
DVWA → XSS (Reflected)

## Reproduction Steps
1. Navigate to `http://localhost:8080/DVWA/vulnerabilities/xss_r/`
2. Enter payload:
   ```html
   <script>alert('XSS')</script>
3. JavaScript alert is executed
4. Bonus: Cookie theft test:
    <script>alert(document.cookie)</script>
## Impact
 - Session theft via cookies

 - Browser hijacking

 - Client-side script injection

## Recommendations
 - Sanitize and encode output (e.g., htmlspecialchars() in PHP)

 - Use modern frameworks with automatic escaping

 - Enforce CSP headers to restrict script sources




