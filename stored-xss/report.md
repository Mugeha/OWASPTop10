# Stored Cross-Site Scripting (XSS) – Vulnerability Report

## Summary

A Stored XSS vulnerability was discovered in DVWA’s Guestbook module. Malicious JavaScript input submitted through the message form is stored in the database and executed whenever any user accesses the page, including administrators and future visitors.

## Affected Module

DVWA → XSS (Stored)

## Reproduction Steps

1. Navigate to:

http://localhost:8080/DVWA/vulnerabilities/xss_s/
3. Set DVWA Security to Low
4. Input the following:
- Name: `Attacker`
- Message:
  ```html
  <script>alert('Stored XSS')</script>
  ```
4. Submit the form

Result: An alert box is triggered **every time the page loads**, confirming persistent script execution.

## Additional Payloads Tested

Cookie access:
```html
<script>alert(document.cookie)</script>
Fake image:

<img src=x onerror="alert('Image-based XSS')">
```
## Impact

Stored XSS affects every user visiting the page

Attackers can steal cookies, credentials, or perform actions as the victim (session hijack)

Admins are at risk if their panels render user content

### Recommendations
Sanitize all inputs before storing in the database

Use htmlspecialchars() or equivalent to encode output

Apply strict Content Security Policy (CSP)

Avoid rendering raw HTML from user input without validation
