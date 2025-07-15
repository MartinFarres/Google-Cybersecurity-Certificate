# Assets, Threats, and Vulnerabilities

**Module 1: Introduction to Asset Security**

**Module 2: Protect Organizational Assets**

**Module 3: Vulnerabilities in Systems**

**Module 4: Threats to asset Security**

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

```
the openssl command reverses the encryption of the file with a secure symmetric cipher, as indicated by AES-256-CBC. The -pbkdf2 option is used to add extra security to the key, and -a indicates the desired encoding for the output. The -d indicates decrypting, while -in specifies the input file and -out specifies the output file. The -k specifies the password, which in this example is ettubrute.
```
