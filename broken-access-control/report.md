# Broken Access Control – Vulnerability Report

## Summary
A Broken Access Control vulnerability was identified in DVWA where insecure direct object references (IDOR) allow users to access data or actions they are not authorized for. This bypasses role-based access and could expose sensitive user records.

## Affected Module
DVWA → Insecure ID

## Reproduction Steps
1. Navigate to `http://localhost:8080/DVWA/vulnerabilities/fi/`
2. Interact with the vulnerable file to fetch specific user IDs
3. Manually change the `id=` value in the URL to access data belonging to another user

## Example
Changing:
?id=1
To:
?id=2
Revealed another user's private data, confirming an IDOR vulnerability.

## Impact
- User impersonation
- Unauthorized data access
- Bypass of business logic and permissions

## Recommendations
- Use access control checks server-side
- Avoid using predictable object references in URLs
- Apply role-based access checks consistently
