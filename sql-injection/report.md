# SQL Injection – Vulnerability Report

## Summary
DVWA's User ID input is vulnerable to SQL Injection, allowing attackers to extract database contents and bypass authentication using specially crafted input.

## Affected Module
DVWA → SQL Injection (Low Security)

## Reproduction Steps
1. Navigate to `http://localhost:8080/DVWA/vulnerabilities/sqli/`
2. Enter payload:
1' OR '1'='1

3. All user records are displayed

4. Bonus: Login bypass using:
- Username: `' OR 1=1 --`
- Password: *(blank)*

## Impact
- Full user data exposure
- Authentication bypass
- Potential for database destruction

## Recommendations
- Use parameterized queries (prepared statements)
- Sanitize input and enforce strong data types
- Apply least privilege to DB user roles

