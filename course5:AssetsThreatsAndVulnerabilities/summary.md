# Assets, Threats, and Vulnerabilities

[**Module 1: Introduction to Asset Security**](#module-1-introduction-to-asset-security)

[**Module 2: Protect Organizational Assets**](#module-2-protect-organizational-assets)

[**Module 3: Vulnerabilities in Systems**](#module-3-vulnerabilities-in-systems)

[**Module 4: Threats to asset Security**]()

---

## Module 1: Introduction to Asset Security

### Understanding Risk, Threats, and Vulnerabilities in Security

Clear communication and coordination are essential during security events, especially when addressing risks to organizational assets. Three foundational terms—**risk**, **threat**, and **vulnerability**—have specific meanings in cybersecurity and are critical to planning and response.

- **Risk** is anything that could impact the **confidentiality, integrity, or availability** of an asset. It’s often calculated as:

  ```
  Risk = Likelihood × Impact
  ```

  Organizations assess risk differently based on their unique assets and priorities. Managing risk helps prevent disruption, guide improvements, and prioritize critical systems.

- **Threats** are potential events or actions that could negatively affect assets. These can be:

  - **Intentional** (e.g., a hacker exploiting a system)
  - **Unintentional** (e.g., an employee accidentally letting in an unauthorized person)

- **Vulnerabilities** are weaknesses that threats can exploit. These fall into:

  - **Technical** (e.g., misconfigured software)
  - **Human** (e.g., lost access cards)

Ultimately, **risk exists when a threat can exploit a vulnerability**. Security professionals focus on reducing the **likelihood** of threats materializing by addressing both human and technical weaknesses.

### Asset Clasification

**Asset management** is the process of tracking assets and the risks that affect them. The idea behind this process is simple: you can only protect what you know you have.

**Asset classification** is the practice of labeling assets based on sensitivity and importance to an organization. Determining each of those two factors varies, but the sensitivity and importance of an asset typically requires knowing the following:

- What you have

- Where it is

- Who owns it, and

- How important it is

The most common classification scheme is: restricted, confidential, internal-only, and public.

- **Restricted** is the highest level. This category is reserved for incredibly sensitive assets, like need-to-know information.

- **Confidential** refers to assets whose disclosure may lead to a significant negative impact on an organization.

- **Internal-only** describes assets that are available to employees and business partners.

- **Public** is the lowest level of classification. These assets have no negative consequences to the organization if they’re released.

### Digital and physical assets

Data can exist in three states:

- **in use:** This refers to data that is actively being accessed or processed by one or more users.

- **in transit:** This is data that is traveling from one location to another, such as when you send an email or transfer files over the internet.

- **at rest:**This describes data that is not currently being accessed or processed. It is typically stored on a physical device, such as a hard drive or cloud storage.

### Risk and Asset Security

Type of risk categories:

- Damage
- Disclosure
- Loss of Information

A Security plan is form by:

- **Policies**: A set of rules that reduce risk and protect information. They provide guidance on what is being protected and why, focusing on the strategic aspects of security.
- **Standars**: Tactical references that inform how to implement policies. They create benchmarks for security practices, such as specifying password requirements.
- **Procedures**: Step-by-step instructions for performing specific security tasks. They ensure consistency and accountability in executing security measures across the organization

**Compliance** is the process of adhering to internal standards and external regulations

#### NIST Cybersecurity Framework (CSF)

A voluntary framework that consists of standards, guidelines, adn best practices to manage cybersecurity risk. Its compose by:

- **Core**: Simplified duties of a security plan. Five core functions:

1. Identify
2. Protect
3. Detect
4. Responds
5. Recover
6. Govern

These functions are commonly used as an informative reference to help organizations _identify_ their most important assets and _protect_ those assets with appropriate safeguards. The CSF core is also used to understand ways to _detect_ attacks and develop _response_ and _recovery_ plans should an attack happen.

- **Tiers**: These provide security teams with a way to measure performance across each of the five functions of the core. Goes from level 1 to 4, 4 being that a duty is being well performed.

- **Profiles**: Provide insight into the current state of a security plan. They are used to help organizations develop a baseline for their cybersecurity plans, or as a way of comparing their current cybersecurity posture to a specific industry standard.

## Module 2: Protect Organizational Assets

### Safeguard Information

**Security Controls** are safeguards designed to reduce specific security risks.

Types of security controls:

- Technical: Technologies to protect assets. Encryption, authentication systems.
- Operational: Mantaining the day to day environment. Training, incident reponse.
- Managerial: Center around how the other two reduced risks. Policies, standards and procedures

**Information privacy** is the protection of unauthorized access and distribution of data.

Security controls should limit the access based on the user and situation. This goes with the concept of the **Principle of least privilige**, is the concept of granting only the minimal access and authorization required to complete a task or funcion.

**Data Custodian**: Anyone or anything that's responsible fot the safe handling, transport and storage of information.

#### The Data Lifecycle

![alt text](/course5:AssetsThreatsAndVulnerabilities/resources/data-lifecycle.png)

#### Data Lifecycle and Governance

Organizations must protect data throughout its entire lifecycle—**collect**, **store**, **use**, **archive**, and **destroy**—to maintain confidentiality, integrity, and availability. A **data governance** framework assigns clear roles:

- **Data Owner**: defines access, usage, and retention policies
- **Data Custodian**: implements security controls and handles data safely
- **Data Steward**: enforces governance policies

Effective governance combines people, processes, and technology to ensure data remains private and recoverable. Special categories of sensitive information—**PII** (identifies individuals), **PHI** (health data under HIPAA/GDPR), and **SPII** (highly sensitive PII like credentials)—require stricter controls. By embedding security policies at each stage and respecting regulatory requirements, organizations can mitigate risks and uphold data privacy.

#### Information Security vs. Information Privacy

- **Privacy** governs how personal data is collected, used, and shared—ensuring individuals control their own information and consent to its processing.
- **Security (InfoSec)** focuses on protecting data in all states (at rest, in use, in transit) from unauthorized access or threats.

A retail example: a company must disclose what customer data (age, location) it collects and allow opt‑out (privacy), then implement access controls, encryption, and monitoring to keep that data safe (security).

Key regulations—**GDPR**, **PCI DSS**, and **HIPAA**—define both privacy rights and required security measures. Organizations validate compliance through **audits** (periodic reviews against standards) and **assessments** (regular checks of security resilience), maintaining both data privacy and robust defenses.

### Encryption Methods

#### Public Key Infraestructure (PKI)

is an encryption framework that secures the exchange of information online.

**Asymetric encryprion**: The use of a public and private key pair for encryption and decryption of data.
**Symetric encryption**: The use of a single secret key to exchange information.

#### PKI Process

1. Exchange of encrypted information.
2. Establish trust using a system of digital certificates

**Digital Certificate** is a file that verifies the identity of a public key holder.
![alt text](/course5:AssetsThreatsAndVulnerabilities/resources/obtaining-digital-certificate.png)

#### Encryption Essentials: Key Length & Algorithms

- **Key Length & Security Trade‑off**
  Longer keys exponentially increase brute‑force resistance but incur slower processing. Balancing performance and protection is crucial for modern systems.

- **Symmetric Ciphers**

  - **3DES**: Applies three 56‑bit DES keys (168‑bit effective), now waning due to data‑volume limits.
  - **AES**: Supports 128, 192, or 256‑bit keys; 128‑bit AES is estimated to resist brute‑force attacks for billions of years.

- **Asymmetric Ciphers**

  - **RSA**: Uses paired public/private keys of 1,024 to 4,096 bits for highly sensitive data.
  - **DSA**: NIST standard with 2,048‑bit keys, often used alongside RSA in PKI.

- **Key Generation & Maintenance**
  Tools like OpenSSL create and manage key pairs; keeping such software up‑to‑date (e.g., post‑Heartbleed) is vital.

- **Kerckhoff’s Principle**
  Security must rely solely on secret keys, not on obscuring algorithm details.

- **Real‑World Use & Compliance**
  Hybrid encryption—public‑key for setup, symmetric for bulk data—underpins secure web sessions and meets regulations like FIPS 140‑3 and GDPR.

#### Lab - Decrypting and Encrypting messages

```bash
cat .leftShift3 | tr "d-za-cD-ZA-C" "a-zA-Z"
```

The `tr` command translates text from one set of characters to another, using a mapping. The first parameter to the `tr` command represents the input set of characters, and the second represents the output set of characters. Hence, if you provide parameters “abcd” and “pqrs”, and the input string to the tr command is “ac”, the output string will be “pr".

```bash
openssl aes-256-cbc -pbkdf2 -a -d -in Q1.encrypted -out Q1.recovered -k ettubrute
```

The openssl command reverses the encryption of the file with a secure symmetric cipher, as indicated by AES-256-CBC. The -pbkdf2 option is used to add extra security to the key, and -a indicates the desired encoding for the output. The -d indicates decrypting, while -in specifies the input file and -out specifies the output file. The -k specifies the password, which in this example is ettubrute.

#### Non-repudiation and Hashing

**Non-repudiation**: The concept that the authenticity of information can't be denied.

```bash
sha256sum output.png
b50581ab859ee9de0f7a31af9be332d091f0146b64adecf0871b9db2c4c445e1  output.png
```

#### Evolution of Hash Functions

Hash functions are fundamental for data integrity and non‑repudiation, transforming arbitrary‑length input into fixed‑size digests.

**Origins & MD5**

- Early hashes like **MD5** (developed by Ronald Rivest in the 1990s) produce a 128‑bit value (32‑character hex).
- MD5 enabled quick integrity checks over networks but soon proved vulnerable: its limited output space allowed attackers to craft **collisions** (different inputs mapping to the same hash).

**Collision Resistance & the SHA Family**
![alt text](/course5:AssetsThreatsAndVulnerabilities/resources/hash-collisions.png)

- To mitigate collision attacks, NIST standardized the **SHA** series:

  - **SHA‑1** (160‑bit)—later found weak against collisions
  - **SHA‑224**, **SHA‑256**, **SHA‑384**, **SHA‑512**—offering progressively larger digests and stronger collision resistance

- Longer hash outputs exponentially increase the effort needed for brute‑force or collision attacks.

**Password Storage & Rainbow Tables**
![alt text](/course5:AssetsThreatsAndVulnerabilities/resources/salt.png)

- Storing raw hashes in user databases exposes them to **rainbow‑table** attacks—precomputed dictionaries mapping hash → plaintext.
- Attackers can quickly reverse common passwords by matching stolen hashes against large lookup tables.

**Salting & Best Practices**

- A unique, random **salt** appended to each input before hashing produces distinct digests even for identical inputs, rendering rainbow tables ineffective.
- Strong hashing schemes combine salts with algorithms like **bcrypt**, **scrypt**, or **Argon2**, which also incorporate computational cost factors to slow brute‑force attempts.

By evolving from MD5 through the SHA family and adopting salting and key‑stretching techniques, modern systems achieve robust protection against integrity and authentication attacks.

### Authentication, Authorization and Accounting

**Access Controls** are security controls that manage access, authorization, and accountability of information.

#### AAA framework - Authentication

They ask anything attempting to access information this simple question: _who are you?_

**Factors of authentication:**

1. Knowledge: something the user knows
2. Ownership: something the user possesses
3. Characteristics: something the user is

**Single sign-on (SSO)** A technology that combines several different logins into one.
SSO works by automating how trust is established between a user and a service provider. Rather than placing the responsibility on an employee or customer, SSO solutions use trusted third-parties to prove that a user is who they claim to be. This is done through the exchange of encrypted access tokens between the identity provider and the service provider.

Similar to other kinds of digital information, these access tokens are exchanged using specific protocols. SSO implementations commonly rely on two different authentication protocols: LDAP and SAML. LDAP, which stands for Lightweight Directory Access Protocol, is mostly used to transmit information on-premises; SAML, which stands for Security Assertion Markup Language, is mostly used to transmit information off-premises, like in the cloud.

![alt text](/course5:AssetsThreatsAndVulnerabilities/resources/sso.png)

**Multi-factor authentication (MFA)**

#### AAA Framework - Authorization

Determines what the user is allowed to do.

**Separation of duties**: The principle that users should not be given levels of authorization that would allow them to misuse a system.

Securing data over a network: HTTP basic auth and OAuth.

- **Basic auth** works by sending an identifier every time a user communicates with a web page. Vulnerable to attacks because it transmits usernames and password openly over the network. Should use HTTPS

- **OAuth**: Is an open-standard authorization protocol that shares designated access between applications. nstead of requesting and sending sensitive usernames and passwords over the network, OAuth uses API tokens to verify access between you and a service provider.

**API Token**: is a small block of encrypted code that contains information about a user.These tokens contain things like your identity, site permissions, and more.

#### AAA Framework - Accounting

Practice of monitor the access logs of a system. Who, When and What they used.

A **session** is a sequence of network HTTP basic auth requests and responses associated with the same user, like when you visit a website.

Two actions are triggered when the session begins. The first is the creation of a **session ID**. A session ID is a unique token that identifies a user and their device while accessing the system. Session IDs are attached to the user until they either close their browser or the session times out.

The second action that takes place at the start of a session is an exchange of **session cookies** between a server and a user's device. A session cookie is a token that websites use to validate a session and determine how long that session should last. When cookies are exchanged between your computer and a server, your session ID is read to determine what information the website should show you.

**Session hijacking** is an event when attackers obtain a legitimate user's session ID.

#### Identity and Access Management (IAM)

Identity and Access Management (IAM) is the practice of ensuring that only the right users, devices, or software gain access to organizational resources at the right time and for the right reasons. IAM builds on the **principle of least privilege**—granting only necessary rights—and **separation of duties**—dividing critical functions among multiple roles to prevent misuse.

Key IAM components include:

- **Authentication**: Verifying identity via factors you know (password), have (token), or are (biometrics), often strengthened with SSO and MFA.
- **User Provisioning/Deprovisioning**: Creating, updating, and removing digital identities and their permissions as personnel join, change roles, or leave.
- **Authorization Models**:

  - **MAC** (Mandatory Access Control): Centralized, non‑discretionary, need‑to‑know access. Access to information must be granted manually by a central authority or system administrator (e.g., military).
    ![alt text](/course5:AssetsThreatsAndVulnerabilities/resources/MAC.png)
  - **DAC** (Discretionary Access Control): Data owners grant permissions (e.g., file sharing).
    ![alt text](/course5:AssetsThreatsAndVulnerabilities/resources/DAC.png)
  - **RBAC** (Role‑Based Access Control): Access rights tied to job roles.
    ![alt text](/course5:AssetsThreatsAndVulnerabilities/resources/RBAC.png)

Effective IAM relies on integrated directories, policy engines, and audit systems—whether custom‑built or third‑party—to automate access control, minimize errors, and support a secure environment.

## Module 3: Vulnerabilities in Systems

### Flaws in the system

**Exploits** is a way of taking advantage of a vulnerability.

#### Vulnerability Management

1. Identify Vulnerabilities
2. Consider Potential exploits
3. Prepare Defenes against threats
4. Evaluate those defenses

#### Securing CI/CD Pipelines: Overview & Key Vulnerabilities

**What is CI/CD and Why It Matters**
CI/CD automates the software release process from code commit through deployment.

- **Continuous Integration (CI):** Developers merge changes frequently into a central branch. Automated builds and tests run on every commit to catch integration issues early.
- **Continuous Delivery (CD):** Every passing build is automatically pushed to a staging environment and kept in a deployable state, with a manual approval gate before production.
- **Continuous Deployment (CD):** Builds that clear all tests and checks are deployed directly to production without human intervention.

By embedding build, test, and deployment steps into an automated pipeline, teams accelerate release cycles and maintain high software quality—provided the pipeline itself is secured.
![alt text](/course5:AssetsThreatsAndVulnerabilities/resources/ci-cd.png)

**Common CI/CD Pipeline Vulnerabilities**

- **Insecure Dependencies:** Unpatched third‑party libraries can introduce known CVEs during automated builds.
- **Misconfigured Permissions:** Weak or overly broad access to CI/CD tools and repositories allows unauthorized changes.
- **Missing Automated Security Tests:** Omitting SAST, DAST, or compliance checks lets vulnerabilities slip into production.
- **Exposed Secrets:** Hard‑coded API keys, passwords, or tokens in code or pipeline settings can be easily extracted by attackers.
- **Unsecured Build Environments:** Compromised build servers or containers enable attackers to inject malicious code or steal artifacts.

**Defense‑in‑Depth Best Practices**

1. **Embed Security Early (DevSecOps):** Integrate automated security scans (SAST, DAST, SCA) into every pipeline stage.
2. **Enforce Least Privilege:** Apply RBAC and MFA to restrict who can view or modify pipeline configurations.
3. **Automate Dependency Management:** Use tools like Dependabot or Snyk to keep libraries and plugins up-to-date.
4. **Secure Secrets Management:** Store and rotate credentials in vaults (e.g., HashiCorp Vault, AWS Secrets Manager) instead of in code.
5. **Harden Build Infrastructure:** Isolate builds in secure containers or VMs and regularly patch build servers.

By understanding – and embedding security throughout – your CI/CD process, you ensure rapid, reliable, and resilient software delivery.

#### Defense in Depth

A layered approach to vulnerability management that reduces risk. The castle approach.

Defense in Depth Strategy:

1. **Perimeter Layer:** User authentication layer that filters external access. It's function is to only allowed trusted partners to reach the next layer of defense.
2. **Network Layer**: Closly aligned with authorization. Firewalls.
3. **Endpoint Layer**: Devices that have access to the network. Antivirus.
4. **Application Layer**: All interfaces that interact with tecnology. Security measures are program into the application. MFA.
5. **Data Layer**: Here we have the SPII data. Assets Classification.

#### Common Vulnerabilities and Exposures

**Exposure** is a mistake that can be exploited by a threat.

[**Common Vulnerabilities and Exposure List (CVE List)**](https://www.cve.org/) is an openly accessible dictionary of known vulnerabilities and exposures.

**CVE Numbering Authority (CNA)** is an organization that volunteers to analyze and distribute information on elegible CVEs.

CVE list criteria:

1. Independent of other issues
2. Recognized as a potential security risk
3. Submitted with supporting evidence
4. Only affect one codebase.

#### Common Vulnerabilities

Businesses often base critical security decisions on the OWASP Top 10—a guide for designing new software—whereas the CVE® list helps identify flaws in existing programs. Below are the most common vulnerabilities ranked by OWASP:

1. Broken Access Control

Failures in enforcing user permissions can allow unauthorized disclosure, modification, or destruction of data. For example, a blog that lets visitors post comments but not delete articles may be misconfigured—enabling attackers to manipulate or erase content, or even gain access to other applications.

2. Cryptographic Failures

Weak or missing encryption exposes sensitive data (e.g., PII) to theft. Using outdated algorithms like MD5 for hashing can lead to data breaches, and non‑compliance with privacy laws (such as GDPR) can incur heavy penalties.

3. Injection

When untrusted input is sent to an interpreter (e.g., SQL, OS commands), attackers can execute malicious code under the guise of normal application behavior. A vulnerable login form, for instance, may allow credential theft or database manipulation via SQL injection.

4. Insecure Design

Lack of built‑in security controls during application design leads to systemic weaknesses (e.g., missing input validation or improper error handling). Such flaws increase susceptibility to injection, malware, and other attacks.

5. Security Misconfiguration

Default settings or unpatched misconfigurations across servers, frameworks, or platforms can expose sensitive functionality. For example, deploying a web server with default credentials or open ports invites unauthorized access.

6. Vulnerable and Outdated Components

Relying on unmaintained open‑source libraries or plugins introduces known CVEs into your application. Regularly updating and scanning dependencies is crucial to prevent exploitation of outdated components.

7. Identification and Authentication Failures

Flaws in verifying user identity—such as broken login flows or weak session management—allow attackers to impersonate legitimate users. A compromised Wi‑Fi router login illustrates how identification failures can expose networks.

8. Software and Data Integrity Failures

Insufficient verification of software updates or CI/CD artifacts can enable supply‑chain attacks. The 2020 SolarWinds breach is a prominent example, where malicious code injected into legit updates was distributed to thousands of customers.

9. Security Logging and Monitoring Failures

Inadequate logging or alerting delays breach detection and incident response. Without comprehensive audit trails (e.g., user logins, configuration changes), it’s difficult to investigate or contain security incidents.

10. Server‑Side Request Forgery (SSRF)

When a web application fails to validate outgoing requests, attackers can coerce the server into fetching or modifying internal resources. SSRF can expose sensitive metadata or grant lateral movement within a private network.

---

By understanding and proactively addressing these vulnerabilities, organizations can design, build, and maintain more resilient applications.

#### OSINT Tools

There’s an enormous amount of open-source information online. Finding relevant intelligence requires specialized tools and techniques. Here are a few examples to explore:

- **[VirusTotal](https://www.virustotal.com/)**
  A free service that analyzes suspicious files, domains, URLs, and IP addresses for malicious content by aggregating results from multiple antivirus engines and website scanners.

- **[MITRE ATT\&CK®](https://attack.mitre.org/)**
  A comprehensive knowledge base of adversary tactics and techniques based on real-world observations, useful for mapping attacker behavior and planning defensive strategies.

- **[OSINT Framework](https://osintframework.com/)**
  A web-based directory of OSINT tools organized by category (e.g., social media, whois, metadata), making it easy to discover specialized utilities for various information sources.

- **[Have I Been Pwned](https://haveibeenpwned.com/)**
  A searchable database that lets you check whether an email address or domain has appeared in known data breaches.

### Identify System Vulnerabilities

#### Vulnreability Assessment

The internal review process of an organization's security systems.

Vulnerability Assessment Process:

1. Identification
2. Vulnerability Analysis. Try to find the source
3. Risk Assessment. Asign a score to the risk. How severe it is and how likely it is.
4. Remediation. Addressing the Risk.

#### Vulnerability Scanning

A **vulnerability scanner** is software that automatically compares known vulnerabilities and exposures against the technologies on the network. In general, these tools scan systems to find misconfigurations or programming flaws.

Vulnerability scanners are meant to be non-intrusive. Meaning, they don’t break or take advantage of a system like an attacker would. Instead, they simply scan a surface and alert you to any potentially unlocked doors in your systems.

_External scans_ test the perimeter layer outside of the internal network. They analyze outward facing systems, like websites and firewalls. These kinds of scans can uncover vulnerable things like vulnerable network ports or servers.

_Internal scans_ start from the opposite end by examining an organization's internal systems. For example, this type of scan might analyze application software for weaknesses in how it handles user input.

_Authenticated scans_ might test a system by logging in with a real user account or even with an admin account. These service accounts are used to check for vulnerabilities, like broken access controls.

_Unauthenticated scans_ simulate external threat actors that do not have access to your business resources. For example, a scan might analyze file shares within the organization that are used to house internal-only documents. Unauthenticated users should receive "access denied" results if they tried opening these files. However, a vulnerability would be identified if you were able to access a file.

_Limited scans_ analyze particular devices on a network, like searching for misconfigurations on a firewall.

_Comprehensive scans_ analyze all devices connected to a network. This includes operating systems, user databases, and more.

#### Penetration Testing

A penetration test, or pen test, is a simulated attack that helps identify vulnerabilities in systems, networks, websites, applications, and processes. The simulated attack in a pen test involves using the same tools and techniques as malicious actors in order to mimic a real life attack. Since a pen test is an authorized attack, it is considered to be a form of ethical hacking.

### Protect All entry points

An important part of this is getting a sense of their attack surface. An **attack surface** is all the potential vulnerabilities that a threat actor could exploit. Analyzing the attack surface is usually the first thing security teams do.

- **Physical Attack Surface**: made up of people and their devices. This surface can be attacked from both inside and outside the organization.In general, the physical attack surface should be filled with obstacles that deter attacks from happening. We call this process security hardening. **Security hardening** is the process of strengthening a system to reduce its vulnerabilities and attack surface. In other words, hardening is the act of minimizing the attack surface by limiting its points of entry.

- **Digital Attack Surface**: includes everything that's beyond our organization's firewall. It includes anything that connects to an organization online. Cloud computing has essentially expanded the digital attack surface. Quicker access to information is something we all benefit from, but it comes with a cost.Organizations of all sizes are under more pressure to defend against threats coming from different entry points.

#### Threat Actors and Attack Surfaces

- **Threat Actor**: Any person or group posing a security risk—intentional or accidental—inside or outside the organization.

  - **Competitors**: Rival companies seeking to exploit leaked information.
  - **State Actors**: Government intelligence agencies.
  - **Criminal Syndicates**: Organized crime groups profiting from illicit activity.
  - **Insider Threats**: Current or former employees who misuse or accidentally expose assets.
  - **Shadow IT**: Unauthorized technologies (e.g., personal email for work) that bypass governance.

- **Hackers** (umbrella term for unauthorized access):

  - **Unauthorized (Malicious)**: Includes “script kiddies” using pre‑written tools.
  - **Authorized (Ethical)**: Internal or contracted testers (e.g., bug bounties).
  - **Semi‑Authorized**: Hacktivists or others with non‑criminal but boundary‑pushing motives.

- **Advanced Persistent Threats (APTs)**: Stealthy, long‑term intrusions—often state‑sponsored—aimed at sustained intelligence gathering or manipulation.

- **Common Attack Vectors**:

  - Physical/direct access
  - Removable media (USB drives)
  - Email (phishing) and social media
  - Wireless networks
  - Cloud services
  - Third‑party supply chains

Understanding each actor’s motivation and likely vectors helps security teams tailor defenses and limit an organization’s attack surface.

#### Pathways Through Defenses

**Attack Vector** are the pathways attackers use to penetrate security defenses.

**Practicing an attacker mindset**:

1. Identify a target
2. Determine how the target can be accessed
3. Evaluate attack vector that can be exploited
4. Find the tools and methods of attacks

**Defending attack vectors**:

1. Educating users
2. Applying the principle of least privilige
3. Using the right security controls and tools

#### Defending Against Brute‑Force Attacks

Brute‑force attacks—trial‑and‑error guessing of usernames, passwords, or encryption keys—are automated with tools like **Aircrack‑ng**, **Hashcat**, and **John the Ripper**. Variants include **dictionary attacks** (using common credentials), **reverse brute force** (one credential against many systems), and **credential stuffing** (reusing breached logins or hashes).

Effective defenses combine technical and managerial controls:

- **Hashing & Salting**: Adds randomness to password hashes, making precomputed and dictionary attacks impractical.
- **Multi‑Factor Authentication (MFA)**: Requires additional verification steps, blocking attackers even if passwords are compromised.
- **CAPTCHA**: Ensures login attempts come from humans, not automated scripts.
- **Strong Password Policies**: Enforce length, complexity, lockout thresholds, and regular rotation—expanding the keyspace and delaying attackers.

By layering these measures—secure storage of credentials, user identity verification, human‑only challenges, and robust policies—organizations can drastically reduce the risk and impact of brute‑force compromises.
