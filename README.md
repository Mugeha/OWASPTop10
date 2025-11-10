# OWASP Mobile

## M1: Improper Credential Usage

### Threat Agents

### Application Specific

Threat agents exploiting hardcoded credentials and improper credential usage in mobile applications can include automated attacks using publicly available or custom-built tools. Such agents could potentially locate and exploit hardcoded credentials or exploit weaknesses due to improper credential usage.

### Attack Vectors
Exploitability EASY

Adversaries can exploit vulnerabilities in both hardcoded credentials and improper credential usage. Once these vulnerabilities are identified, an attacker can use hardcoded credentials to gain unauthorized access to sensitive functionalities of the mobile app. They can also misuse credentials, for instance by gaining access through improperly validated or stored credentials, thereby bypassing the need for legitimate access.

### Security Weakness
Prevalence COMMON

#### Detectability EASY

Poor implementation of credential management, such as using hardcoded credentials and improper handling, can lead to severe security weaknesses. A comprehensive security testing process should aim to identify these issues. For instance, security testers should attempt to identify hardcoded credentials within the mobile app’s source code or within any configuration files.

### Technical Impacts
Impact SEVERE

Poor credential management can lead to several significant technical impacts. Unauthorized users might gain access to sensitive information or functionality within the mobile app or its backend systems. This can lead to data breaches, loss of user privacy, fraudulent activity, and potential access to administrative functionality.

### Business Impacts
Impact SEVERE

The business impact of poor credential management, including hardcoded credentials and improper credential usage, can be substantial:

Reputation Damage
Information Theft
Fraud
Unauthorized Access to Data.

### Am I Vulnerable To ‘Improper Credential Usage’?
Insecure credential management can occur when mobile apps use hardcoded credentials or when credentials are misused. Here are some indicators that your mobile app may be vulnerable:

Hardcoded Credentials - If the mobile app contains hardcoded credentials within the app’s source code or any configuration files, this is a clear indicator of vulnerability.
Insecure Credential Transmission - If credentials are transmitted without encryption or through insecure channels, this could indicate a vulnerability.
Insecure Credential Storage - If the mobile app stores user credentials on the device in an insecure manner, this could represent a vulnerability.
Weak User Authentication - If user authentication relies on weak protocols or allows for easy bypassing, this could be a sign of vulnerability.

### How Do I Prevent ‘Improper Credentials Usage’?
Avoiding insecure credential management involves not using hardcoded credentials and properly handling user credentials.

Avoid Using Hardcoded Credentials

Hardcoded credentials can be easily discovered by attackers and provide an easy access point for unauthorized users. Always avoid using hardcoded credentials in your mobile app’s code or configuration files.

Properly Handle User Credentials

User credentials should always be stored, transmitted, and authenticated securely:

Encrypt credentials during transmission.
Do not store user credentials on the device. Instead, consider using secure, revocable access tokens.
Implement strong user authentication protocols.
Regularly update and rotate any used API keys or tokens.
### Example Attack Scenarios
The following scenarios showcase improper credentials usage in mobile apps:

Scenario #1: Hardcoded Credentials: An attacker discovers hardcoded credentials within the mobile app’s source code. They use these credentials to gain unauthorized access to sensitive functionality within the app or backend systems.

Scenario #2: Insecure Credential Transmission: An attacker intercepts insecurely transmitted credentials between the mobile app and its backend systems. They use these intercepted credentials to impersonate a legitimate user and gain unauthorized access.

Scenario #3: Insecure Credential Storage: An attacker gains physical access to a user’s device and extracts stored credentials from the mobile app. The attacker uses these credentials to gain unauthorized access to the user’s account.

### References

OWASP
[OWASP](https://www.owasp.org/index.php/OWASP_Top_Ten)

External
[External References](http://cwe.mitre.org/)


## M2: Inadequate Supply Chain Security

### Threat Agents
### Application Specific

An attacker can manipulate application functionality by exploiting vulnerabilities in the mobile app supply chain. For example, an attacker can insert malicious code into the mobile app’s codebase or modify the code during the build process to introduce backdoors, spyware, or other malicious code.

This can allow the attacker to steal data, spy on users, or take control of the mobile device. Moreover, an attacker can exploit vulnerabilities in third-party software libraries, SDKs, vendors, or hardcoded credentials to gain access to the mobile app or the backend servers.

This can lead to unauthorized data access or manipulation, denial of service, or complete takeover of the mobile app or device.

### Attack Vectors

Exploitability AVERAGE

There are multiple ways to exploit Inadequate Supply Chain vulnerability for example- an insider threat agent or an attacker can inject malicious code during the development phase of the app, then they can compromise the app signing keys or certificates to sign malicious code as trusted.

Another way, a threat agent can exploit vulnerabilities in third-party libraries or components used in the app.

### Security Weakness

Prevalence COMMON

### Detectability DIFFICULT

Inadequate Supply Chain vulnerability occurs due to a lack of secure coding practices, insufficient code reviews and testing leading to the inclusion of vulnerabilities in the app.

Other causes for inadequate supply chain vulnerabilities include insufficient or insecure app signing and distribution process, weakness in third-party software components or libraries, insufficient security controls for data, encryption, storage, or exposing sensitive data to unauthorized access.

### Technical Impacts
Impact SEVERE

If an attacker successfully exploits inadequate supply chain security, the technical impact can be severe. The specific technical impact depends on the nature of the exploit, but it can include:

- Data Breach: The attacker can steal sensitive data, such as login credentials, personal data, or financial information. The data breach can have long-term consequences for the affected individuals, such as identity theft or financial fraud.

- Malware Infection: The attacker can introduce malware into the mobile application, which can infect the user’s device and steal data or perform malicious activities. The malware can be difficult to detect and remove, and it can cause significant damage to the user’s device and data.

- Unauthorized Access: The attacker can gain access to the mobile application’s server or the user’s device and perform unauthorized activities, such as modifying or deleting data. This can result in data loss, service disruption, or other technical issues.

- System Compromise: The attacker can compromise the entire system of the mobile application, which can lead to a complete loss of control over the system. This can result in the shutdown of the application, significant data loss, and long-term damage to the reputation of the mobile application developer.

### Business Impacts

Impact SEVERE

If an attacker successfully exploits inadequate supply chain security, the business impact can be significant. The specific business impact depends on the nature of the exploit and the organization’s size, industry, and overall security posture, but it can include:

- Financial Losses: The organization can suffer financial losses as a result of the attack, such as the cost of investigating the breach, the cost of notifying affected individuals, or the cost of legal settlements. The organization can also lose revenue if customers lose trust in the mobile application and stop using it.

- Reputational Damage: The organization can suffer reputational damage as a result of the attack, which can lead to long-term damage to the organization’s brand and customer trust. This can result in reduced revenue and difficulty in attracting new customers.

- Legal and Regulatory Consequences: The organization can face legal and regulatory consequences as a result of the attack, such as fines, lawsuits, or government investigations. These consequences can result in significant financial and reputational damage to the organization.

- Supply Chain Disruption: The attack can disrupt the organization’s supply chain and lead to delays or interruptions in the delivery of goods or services. This can result in financial losses and reputational damage to the organization.

### Am I vulnerable to ‘Inadequate Supply Chain Vulnerability’?

It is possible that you are vulnerable to inadequate supply chain vulnerability, particularly if you use mobile applications that are developed by third-party developers or rely on third-party libraries and components. The vulnerability can arise due to a variety of reasons, such as:

- Lack of Security in Third-Party Components: Third-party components, such as libraries or frameworks, can contain vulnerabilities that can be exploited by attackers. If the mobile application developer does not vet the third-party components properly or keep them updated, the application can be vulnerable to attacks.

- Malicious Insider Threats: Malicious insiders, such as a rogue developer or a supplier, can introduce vulnerabilities into the mobile application intentionally. This can occur if the developer does not implement adequate security controls and monitoring of the supply chain process.

- Inadequate Testing and Validation: If the mobile application developer does not test the application thoroughly, it can be vulnerable to attacks. The developer may also fail to validate the security of the supply chain process, leading to vulnerabilities in the application.

- Lack of Security Awareness: If the mobile application developer does not have adequate security awareness, they may not implement the necessary security controls to prevent supply chain attacks.

### How Do I Prevent ‘Inadequate Supply Chain Vulnerability’?

- Implement secure coding practices, code review, and testing throughout the mobile app development lifecycle to identify and mitigate vulnerabilities.
- Ensure secure app signing and distribution processes to prevent attackers from signing and distributing malicious code.
- Use only trusted and validated third-party libraries or components to reduce the risk of vulnerabilities.
- Establish security controls for app updates, patches, and releases to prevent attackers from exploiting vulnerabilities in the app.
- Monitor and detect supply chain security incidents through security testing, scanning, or other techniques to detect and respond to incidents in a timely manner.
  
### Example Attack Scenarios

Scenario #1 Malware Injection

An attacker injects malware into a popular mobile app during the development phase. The attacker then signs the app with a valid certificate and distributes it to the app store, bypassing the app store’s security checks. Users download and install the infected app, which steals their login credentials and other sensitive data. The attacker then uses the stolen data to commit fraud or identity theft, causing significant financial harm to the victims and reputational damage to the app provider.

### References

OWASP

[Supply Chain Vulnerabilities](https://owasp.org/www-project-kubernetes-top-ten/2022/en/src/K02-supply-chain-vulnerabilities)

[OWASP Dependency Check](https://owasp.org/www-project-dependency-check/)

External

[External References](http://cwe.mitre.org/)


M3: Insecure Authentication/Authorization
Threat Agents
Application Specific

Threat agents that exploit authentication and authorization vulnerabilities typically do so through automated attacks that use available or custom-built tools.

Attack Vectors
Exploitability EASY

Once the adversary understands the vulnerabilities in either the authentication or authorization scheme, they can exploit these weaknesses in one of two ways. They may either fake or bypass the authentication by directly submitting service requests to the mobile app’s backend server, circumventing any direct interaction with the mobile app, or they can log into the application as a legitimate user after successfully passing the authentication control and then force-browse to a vulnerable endpoint to execute administrative functionality. Both exploitation methods are typically accomplished via mobile malware within the device or botnets owned by the attacker.

Security Weakness
Prevalence COMMON

Detectability AVERAGE

In order to test for poor authorization and authentication schemes in mobile apps, a number of strategies can be employed by testers. For authorization, testers can perform binary attacks against the mobile app and try to execute privileged functionality that should only be executable with a user of higher privilege, particularly while the mobile app is in ‘offline’ mode. Testers should also attempt to execute any privileged functionality using a low-privilege session token within the corresponding POST/GET requests for the sensitive functionality to the backend server.

Poor or missing authorization schemes can potentially allow an adversary to execute functionality they should not be entitled to using an authenticated but lower-privilege user of the mobile app. This risk of privilege escalation attack is heightened when authorization decisions are made within the mobile device instead of through a remote server, a scenario that can often arise due to the mobile requirements of offline usability.

In terms of poor authentication schemes, testers can undertake binary attacks against the mobile app while it’s in ‘offline’ mode, aiming to bypass offline authentication and then execute functionality that should require offline authentication. Testers should also try to execute any backend server functionality anonymously by removing any session tokens from any POST/GET requests for the mobile app functionality.

Poor or missing authentication schemes can allow an adversary to anonymously execute functionality within the mobile app or the backend server used by the mobile app. These weaknesses in mobile app authentication are fairly common due to the mobile device’s input form factor, which often encourages short passwords or 4-digit PINs.

Mobile apps face unique authentication requirements that can diverge from traditional web authentication schemes, largely due to their varying availability requirements. Unlike traditional web apps where users are expected to be online and authenticate in real-time with a backend server, mobile apps may need to fulfill uptime requirements that necessitate offline authentication due to the unreliability or unpredictability of mobile internet connections. This requirement can significantly impact the factors developers must consider when implementing mobile authentication.

Technical Impacts
Impact SEVERE

The technical impact of poor authorization and authentication in a system can be wide-ranging, significant, and similar, largely depending on the type of over-privileged functionality that is executed. When it comes to poor authorization, for instance, over-privileged execution of remote or local administration functionality may destroy systems or access to sensitive information.

The technical repercussions of poor authentication occur when the solution is unable to identify the user performing an action request. This can immediately result in the inability to log or audit user activity since the user’s identity cannot be established. This lack of identity verification contributes to an inability to detect the source of an attack, understand the nature of any underlying exploits, or devise strategies to prevent future attacks.

Moreover, failures in authentication can also expose underlying authorization failures. When authentication controls fail, the solution is unable to verify the user’s identity, which is closely tied to a user’s role and associated permissions. If an attacker can anonymously execute sensitive functionality, it indicates that the underlying code is not verifying the permissions of the user issuing the request for the action. Consequently, the anonymous execution of code underscores failures in both authentication and authorization controls.

Business Impacts
Impact SEVERE

The business impact of poor authentication and authorization will typically result in the following at a minimum:

Reputation Damage;
Information Theft;
Fraud;
Unauthorized Access to Data.
Am I Vulnerable To ‘Insecure Authentication / Authorization’?
Understanding the difference between authentication and authorization is paramount in evaluating mobile application security. Authentication identifies an individual, while authorization verifies if the identified individual has the necessary permissions for a particular action. These two aspects are closely related, as authorization checks should immediately follow mobile device request authentication.

Insecure authorization can occur when an organization fails to authenticate an individual before executing a requested API endpoint from a mobile device, as it is virtually impossible to conduct authorization checks on an incoming request without an established caller’s identity.

Here are some straightforward indicators of insecure authorization:

Presence of Insecure Direct Object Reference (IDOR) vulnerabilities - Noticing an IDOR vulnerability may suggest that the code isn’t conducting a proper authorization check.
Hidden Endpoints - Developers might neglect authorization checks on backend hidden functionality, assuming that the hidden functionality will only be accessed by a user with the appropriate role.
User Role or Permission Transmissions - Should the mobile app transmit the user’s roles or permissions to a backend system as part of a request, this could signal insecure authorization.
Similarly, mobile apps can exhibit various signs of insecure authentication:

Anonymous Backend API Execution - The ability of the app to execute a backend API service request without providing an access token may point to insecure authentication.
Local Storage of Passwords or Shared Secrets - If the app stores any passwords or shared secrets locally on the device, this could be a sign of insecure authentication.
Weak Password Policy - The use of a simplified password-entering process may imply insecure authentication.
Usage of Features like FaceID and TouchID - Employing features like FaceID or TouchID could be indicative of insecure authentication.
How Do I Prevent ‘Insecure Authentication and Authorization’?
To prevent both insecure authentication and authorization, it’s crucial to avoid weak patterns and reinforce secure measures.

Avoid Weak Patterns

Insecure Mobile Application Authentication Design Patterns should be avoided:

If you are porting a web application to a mobile equivalent, ensure the authentication requirements of mobile applications match that of the web application component. It should not be possible to authenticate with fewer factors than the web browser.
Local user authentication can lead to client-side bypass vulnerabilities. If the application stores data locally, the authentication routine can be bypassed on jailbroken devices through runtime manipulation or binary modification. If offline authentication is a compelling business requirement, consult additional guidance on preventing binary attacks against the mobile app.
Perform all authentication requests server-side, where possible. Upon successful authentication, application data will be loaded onto the mobile device, ensuring application data availability only after successful authentication.
If client-side data storage is necessary, encrypt the data using an encryption key securely derived from the user’s login credentials. However, there are additional risks that the data will be decrypted via binary attacks.
The “Remember Me” functionality should never store a user’s password on the device.
Mobile applications should ideally use a device-specific authentication token that can be revoked within the mobile application by the user, mitigating unauthorized access risks from a stolen/lost device.
Avoid using spoof-able values for user authentication, including device identifiers or geo-location.
Persistent authentication within mobile applications should be implemented as an opt-in and not enabled by default.
Where possible, refrain from allowing users to provide 4-digit PIN numbers for authentication passwords.
Reinforce Authentication

Developers should assume that all client-side authorization and authentication controls can be bypassed by malicious users. Server-side reinforcement of these controls is critical.
Due to offline usage requirements, mobile apps might need to perform local authentication or authorization checks. In such cases, developers should instrument local integrity checks to detect any unauthorized code changes. Consult additional guidance on detecting and reacting to binary attacks.
Use FaceID and TouchID to unlock biometrically locked secrets and securely protect sensitive authentication materials, like session tokens.
Insecure Authorization Prevention

To avoid insecure authorization:

Backend systems should independently verify the roles and permissions of the authenticated user. Do not rely on any roles or permission information that comes from the mobile device.
Assume that all client-side authorization can be bypassed, hence reinforcing server-side authorization controls whenever possible.
If offline authorization checks are necessary within the mobile app’s code, developers should perform local integrity checks to detect unauthorized code changes.
Example Attack Scenarios
The following scenarios showcase weak authentication or authorization controls in mobile apps:

Scenario #1: Hidden Service Requests: Developers assume that only authenticated users will be able to generate a service request that the mobile app submits to its backend for processing. During the processing of the request, the server code does not verify that the incoming request is associated with a known user. Hence, adversaries submit service requests to the back-end service and anonymously execute functionality that affects legitimate users of the solution.

Scenario #2: Interface Reliance: Developers assume that only authorized users will be able to see the existence of a particular function on their mobile app. Hence, they expect that only legitimately authorized users will be able to issue the request for the service from their mobile devices. The back-end code that processes the request does not bother to verify that the identity associated with the request is entitled to execute the service. Hence, adversaries are able to perform remote administrative functionality using fairly low-privilege user accounts.

Scenario #3: Usability Requirements: Due to usability requirements, mobile apps allow for passwords that are 4 digits long. The server code correctly stores a hashed version of the password. However, due to the severely short length of the password, an adversary will be able to quickly deduce the original passwords using rainbow hash tables. If the password file (or data store) on the server is compromised, an adversary will be able to quickly deduce users’ passwords.

Scenario #4: Insecure Direct Object Reference: A user makes an API endpoint request to a backend REST API that includes an actor ID and an OAuth bearer token. The user includes their actor ID as part of the incoming URL and includes the access token as a standard header in the request. The backend verifies the presence of the bearer token but fails to validate the actor ID associated with the bearer token. As a result, the user can tweak the actor ID and attain the account information of other users as part of the REST API request.

Scenario #5: Transmission of LDAP roles: A user makes an API endpoint request to a backend REST API that includes a standard oAuth bearer token along with a header that includes a list of LDAP groups that the user belongs to. The backend request validates the bearer token and then inspects the incoming LDAP groups for the right group membership before continuing on to the sensitive functionality. However, the backend system does not perform an independent validation of LDAP group membership and instead relies upon the incoming LDAP information coming from the user. The user can tweak the incoming header and report to be a member of any LDAP group arbitrarily and perform administrative functionality.

References
OWASP
OWASP
External
External References
