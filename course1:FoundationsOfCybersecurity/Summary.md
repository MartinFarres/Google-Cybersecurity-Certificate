# Unidad 1 - Fundamento de Ciberseguridad

#### 1: Bienvenido al apasionante mundo de la ciberseguridad

#### 2: La evolución de la ciberseguridad

#### 3: Protección frente a amenazas, riesgos y vulnerabilidades

#### 4: Herramientas de ciberseguridad y lenguajes de programación

### Modulo 1:

---

**Cybersecurity**: Es la practica de asegurar la confidencialidad, integridad y la disponibilidad de la informacion mediante la proteccion de redes, dispositivos, personas y datos de acesos no autorizados o explotacion criminal.

**Common job titles**:

- Security analyst or specialist
- Cybersecurity analyst or specialist
- Security operations center (SOC) analyst
- Information security analyst

**Job Responsabilities**:

- Resposible for monitoring and protecting informations and systems

1. Protecting computer and network systems;
2. Install Prevention Software;
3. Conducting periodic security audits;

**Terminologia:**

**Playbook**: Is a list of hot wo go through a certain detection, and what the analyst needs to look at in order to investigate those incidents.

**Threat actor**: actor que demuestra posible peligros.

- External:Persona de afuera de la organizacion
- Internal:Empleados, Empresas con las que se trabaja, etc.

**Cumplimiento Normativo**: proceso de acatar estándares internos y regulaciones externas. Evitar problemas, multas y violaciones de la seguridad.

**Marcos de seguridad**: Directrices para elaborar planes para mitigar riesgos.

**Postura de Seguridad**: capacidad de una organizacion para gestionar su defensa de activos y datos criticos y reaccionar ante los cambios. Una postura de seguridad fuerte conlleva un menor riego para la organizacion.

**Agente de Amenaza**: (Atacante malicioso)

**IDS**: Sistemas de Deteccion de Intrusiones.

**SIEM**: Herramientas de administracion deinformacion y eventos de seguriad.

**Personally Identifiable Information (PII):** Any information used to infer an individual's identity. Nombre, Email, Address, IP, etc.

**Sensitive Personally Identifiable Information (SPII)**: A specific type of PII that falls under stricter handling guidelines. DNI, Datos medicos, Datos biometricos.

## Modulo 2

### Past Cybersecurity attacks:

#### Key terms:

Computer Virus: Malicious code wirten to interfere with computer operations and cause damage to data and software.Se esconden en archivos/ejecutables y se reproducen.

Malware: Software designed to harm devices or networks.

#### The Brain Virus

1986 - El virus se disfrazaba en software pirateados y al ingresar el disco con el virus a la computador la misma se infectaba. El problema era que, luego cualquier disco ingresado en dicho pc tmb se infectaba, reproduciendose asi a miles de computadoras.En un par de meses se habia desplazado a todo el mundo.
En consecuencia, se comenzo a ver la importancia de mantener la seguridad y planes de accion.

#### The Morris Worm

1988 - Programa para ver el tamaño del internet. El programa se replicaba de pc en pc para contabilizarlas. Sin embargo, el programa no poseeia memoria de que pcs ya habia infectado, instalandose así mismo varias veces hasta agotar la memoria de la computadora.
En consecuencia, los Computer Emergencies Response Teams (CERTs), grupos diseñados para responder en situaciones como estas.

### Attacks in the Digital Age

The internet Make all things worse as visrus didnt need to use discs to replicate.

#### LoveLetter attack

2000 - Malware to steel login credentials. Users recieve a love letter through Email. When the attachment was open it scanned the user's address book, and automatically send itself to every contact through the victims email. 45M infected. 10B USD$ in damages.
An example of Social Engineering

**Social Engineering**: A manipulation technique that exploits human error to gain private information, access or valuables.

Consecuences, learned the importance of detecting and preventing social engeneering attacks.

#### Equifax Breach

2017 - Largest known data breach. It contained SPII. The hackers took advantage of several known exploits that the company didnt manage.
Consecuences, it alerted companies of the large financial implication this event has on companies.

### Common attacks and their efectiveness:

#### Phising

It is the use of digiral communications to trick people into revealing sensitive data or deploying malicious software. Most common types are:

- Business Email Compromise ( BEC): n email to seems to be from a seemingly legitimate request for information.
- Spear Phising: A malicious email attack that targets a specific user or group of users. Again the email seems to originate from a trusted source.
- Whaling: Form of spear phising. Targets company executives.
- Vhising: Exploting electronic voice communications to obtain information or to impersonate a known source.
- Smishing: the use of text messages to trick users, in order to obtain sensitive information or to impersonate a known source.

#### Malware

Common types of malware attacks today:

- Viruses: Code written to interfere with computer operations and cause damage to data and software. It needs to be initiated by a threat actor, who trasmits it. When it is open it hides itself in other files. When these files are opened, it allows the virus to insert its own code.
- Worms: It can duplicate and spread itself across systems on its own. Unlike a virus, a worm does not nedd to be downloaded by a user. Instead, it self-replicates and spreads from an already infected computer to other devices on the same network.
- Ransomware: the attackers encrypts the data and demands payment to restore access.
- Spyware: Used to gather and sell information without consent.

#### Social Engineering

A manipulation technique that explorts human error to grain private information, access or valuables. Human error is usually a result of trusting someone without question. The mission of a threat actor is to create an environment of false trust and liest to exploit as many people as possible.

Common types of social engineering attacks today:

- Social Media Phishing:collects detailed information about their target from social media sites.
- Watering Hole Attack: attacks a website frequently visited by a specific group of users.
- USB Baiting: a malware USB strick for an employee to find and install, infecting a network.
- Physical Social Engineering: impersonating an employee, customer, or vendor to obtain unauthorized access to a physical location.

**Social Engineering Principles**:

Reasons why social engineering attacks are effective include:

1.  Authority: Impersonating individuals with power. This is because people have conditioned to respect and follow authority figures.
2.  Intimidation: Use of bullying tactics.
3.  Scarcity: A tactic used to imply that goods or services are in limited supply.
4.  Familiarity: establish a fake emotional connection with users that can be exploited.
5.  Trust: emotional relationship.
6.  Urgency: persuades to respond quickly and without questioning.

### The 8 CISSP Security Domains

Core security concept are grouped into categories called security domains, CISSP.

Gaps in one domain could cause critical problems in other.

#### 1 - Security and Risk Management

Focus on definign security goals and objetives, risk mitigation, compliance, business continuity and the law.

Ex, update organization rules because of law regulation.

#### 2 - Asset Security

Focuses on securing digital and physical Assests. It's also related to the storage, maintenance, retention, and destruction of data.

Ex, tasked with old hardware and make sure it is safely dispose of.

#### 3 - Security Architecture and Engineering

Optimizes data security by ensuring effective tools, systems and processes are in place.

Ex, tasked with configuring a firewall.

#### 4 - Communication and Network Security

Manage and secure physical networks and wireless communications.

Ex, analize user behavior within your organization. Maybe users in your organization are connecting through public and unsafe hotspots. So, the analyst should create a network policy to prevent and minimize exposure.

#### 5 - Identity and Access Management

Keeps data secure by ensuring users follow established policies to control and manage physical assets, like office spaces, and logical assets, such as networks and applications.

Ex, setting employee key cards access

#### 6 - Security assessment and testing

Conducting security control testing, collecting and analyzing data, and conducting security audits to monitor for risks, threats and vulnerabilities.

Ex, access to payrole information is limited to certain roles. So, it should be normal to maintain regular audits and controlls in this roles.

#### 7 - Security Operations

Conducting investigations and implementing preventative measures

Ex, an unknown device has connected to the network. So, the analyst should use the known company playbook to mitigate and stop this threat.

#### 8 - Software Development Security

Uses secure coding practices, which are a set of recommended guidelines that are used to create a secure applications and services.

Ex, ensuring or consulting for the proper encryption and security protocols for managing passwords.

#### Determine the type of Attack

- **Pasword Attack (D4)** : attempt to access password-secured devices, systems, networks or data. Ex, Brute Force, Rainbow Table.

- **Social Engineering Attacks (D1)**

- **Physical Attacks (D2)**

- **Adversarial Artificial Intelligence (D4-5)**: Technique that manipulates a.i and ml technology to conduct attacks more efficiently.

- **Supply Chain Attacks (D1-3-7)**: targets systems, applications, hardware, and/or software to locate a vulnerability where malware can be deployed. Because every item sold undergoes a process that involves a foreign actor, this means that the breach can occur at any point in the supply chain.

- **Cryptographic Attack (D4)**: affects secure forms of communication between a sender and intended recipient. Ex, Birthday, Collision, Downgrade.

### Understanding Attackers

Threat actors are defined by their malicious intent and hackers are defined by their technical skills and motivations. Understanding their motivations and intentions will help you be better prepared to protect your organization and the people it serves from malicious attacks carried out by some of these individuals and groups.

**Threat Actor Types**:

1. Advanced Persistent Threats (APTs)
2. Insider Threats
3. Hacktivists

**Hacker Types**:

1. Authorized Hackers or Ethical Hackers.
2. Semi-authorized Hackers (Researchers like).
3. Unauthorized Hackers.

## Modulo 3

**Security Frameworks** are guidelines used for buildings plans to help mitigate risk and threats to data and privacy
Structure approach to implementing a security life cycle.
Purpose of security frameworks:

- Protecting PII
- Security financial information
- Identifying security weaknesses
- Managing organizaional risks
- Aligning security with business goals

### Components of Frameworks

1. Identifying and documenting security goals. Ex, align with the EU GDPR (Data protection law).

2. Setting guidelines to achive security goals. Ex, while implementing guidelines your organizations may need to develop new guidelines to deal with user data.

3. Implementing strong security processes. Ex, may help introduce a secure guideline such as when a user tries to delete or update their profile information.

4. Monitoring and comminicating results. Ex, report an issue with GDPR guidelines.

### Security Controls

Safeguards designed to reduce specific security risks

### CIA Triad

A foundational **model** that helps inform how organizations consider risk when setting up systems and security
policies.

- **Confidentiality**: Only authorized access. Ex, strict acces control to ensure data maintains confidential.

- **Integrity**: Data is correct, authentic and reliable. It hasnt been tamper with.

- **Availability**: Data is accessible.

#### NIST Cybersecurity Framework (CSF)

A voluntary framework that consists of standars, guidelines, and best practices to manage cybersecurity risk.

### Ethics in Cybersecurity

#### Ethical principles in security:

1. **Confidentiality**: Is your ethical duty to keep data confidential and safe.

2. **Privacy protections**: Safeguarding personal information from unauthorized use. Ex, boss asks for an employee's phone. Accessing that information would be unethical. Recommendation: follow the company's guidelines.

3. **Laws**

#### Ethical concerns and laws related to counterattacks

- **EEUU standpoint**: In the U.S., deploying a counterattack on a threat actor is illegal because of laws like the Computer Fraud and Abuse Act of 1986 and the Cybersecurity Information Sharing Act of 2015, among others. You can only defend. The act of counterattacking in the U.S. is perceived as an act of vigilantism

- **International standpoint**:The International Court of Justice (ICJ), states that a person or group can counterattack if:

  1. The counterattack will only affect the party that attacked first.

  2. The counterattack is a direct communication asking the initial attacker to stop.

  3. The counterattack does not escalate the situation.

  4. The counterattack effects can be reversed.

  Organizations typically do not counterattack because the above scenarios and parameters are hard to measure. There is a lot of uncertainty dictating what is and is not lawful, and at times negative outcomes are very difficult to control. Counterattack actions generally lead to a worse outcome, especially when you are not an experienced professional in the field.

## Modulo 4

**SIEM Tool**: An application that collects and analyzes log data to monito critical activities in an organization

### SPLUNK

is a data analyses platform. Used ro retain,analyze, and search an organization's log data.

### CHRONICLE

Chronicle is a cloud-native SIEM tool that stores security data for search and analysis.
Cloud-native means that Chronicle
allows for fast delivery of new features.

### OTHER SECURITY TOOLS

- Playbooks
- Network protocol analyzers (Packet sniffers)

**Packet Sniffers:** A tool designed to capture and analyze data traffic within a network.

### PLAYBOOKS

- **Chain of Custody Playbook**: is the process of documenting evidence possession and control during an incident lifecycle. Document who, what, where and why you have collected evidence.
- **Protecting and Preserving Playbook**: is the process of properly working with fragile and volatile digital evidence. You will consult the **order of volatility**, which is a sequence outlining the order of data that must be preserved from first to last. It prioritizes colatile data regardless of he reason. When evidence is improperly managed durign an investigation, it can no longer be used.
