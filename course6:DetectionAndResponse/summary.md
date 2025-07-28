# Assets, Threats, and Vulnerabilities

[**Module 1: Introduction to detection and incident response**](#module-1-introduction-to-detection-and-incident-response)

[**Module 2: Network monitoring and analysis**](#module-2-network-monitoring-and-analysis)

[**Module 3: Incident investigation and response**](#module-3-incident-investigation-and-response)

[**Module 4: Network traffic and logs using IDS and SIEM tools**](#module-4-network-traffic-and-logs-using-ids-and-siem-tools)

---

## Module 1: Introduction to detection and incident response

This course will explore the last three steps of the NIST CSF framework: detect, respond and recover.

Incident lifecycle frameworks provide a structure to support incident response operations. Frameworks help organizations develop a standardized approach to their incident response process, so that incidents are managed in an effective and consistent way.

The NIST incident response lifecycle is another NIST framework with additional substeps dedicated to incident response. It begins with preparation. Next, detection and analysis, and then containment, eradication and recovery, and finally post-incident activity. One thing to note is that the incident lifecycle isn't a linear process. It's a cycle, which means that steps can overlap as new discoveries are made.

![alt text](/course6:DetectionAndResponse/resources/incident-lifecycle.png)

**Incident**:an occurrence that actually or imminently jeopardizes, without lawful authority, the confidentiality, integrity, or availability of information or an information system; or constitutes a violation or imminent threat of violation of law, security policies, security procedures, or acceptable use policies.

**Event**: An observable occurrence on a network, system, or device.

The 5 W's of an incident:

- _Who_ triggered the incident
- _What_ happened
- _When_ the incident took place
- _Where_ the incident took place
- _Why_ the incident occured

**Incident handler's journal**: A form of documentation used in incident repsponse.

### Incident Response Operations

Computer security incident response teams, or **CSIRTs**, are a specialized group of security professionals that are trained in incident management and response. The goal of CSIRTs are to effectively and efficiently manage incidents, provide services and resources for response and recovery, and prevent future incidents from occurring.

Roles in CSIRT:

- Security Analyst
- Technical lead
- Incident coordinator

#### Incident Response Plans

Incident plans have:

- Incident response procedures: These are step-by-step instructions on how to respond to incidents.
- System information: These are things like network diagrams,data flow diagrams, logging, and asset inventory information.
- Other documents: like contact lists, forms, and templates.

### Incident Response Tools

Tool Types:

- Detection and management tools: to monitor system actictty to identify events that require investigations.
- Documentation tools: to collect and compile evidence.
- Investigative tools: for analyzing these events, like packet sniffers.

#### Intrusion detection systems (IDS)

An application that moitors system and network activity and produces alerts on possible intrusions

#### Intrusion Prevention System (IPS)

An application that monitors systems activity for instrusions and take action to stop the activity.

IDS and IPS tools:

- Snort
- Zeek
- Kismet
- Sagan
- Suricata

#### Endpoint Detection and Response (EDR)

An application that monitors and endpoint for malicious activity.

#### Detection Categories

As a security analyst, you will investigate alerts that an IDS generates. There are four types of detection categories you should be familiar with:

1. **A true positive** is an alert that correctly detects the presence of an attack
2. **A true negative** is a state where there is no detection of malicious activity. This is when no malicious activity exists and no alert is triggered.
3. **A false positive** is an alert that incorrectly detects the presence of a threat. This is when an IDS identifies an activity as malicious, but it isn't. False positives are an inconvenience for security teams because they spend time and resources investigating an illegitimate alert.
4. **A false negative** is a state where the presence of a threat is not detected. This is when malicious activity happens but an IDS fails to detect it. False negatives are dangerous because security teams are left unaware of legitimate attacks that they can be vulnerable to.

#### IDS, IPS and EDR table

| Capability                   | IDS | IPS | EDR |
| ---------------------------- | :-: | :-: | :-: |
| Detects malicious activity   |  ✓  |  ✓  |  ✓  |
| Prevents intrusions          | N/A |  ✓  |  ✓  |
| Logs activity                |  ✓  |  ✓  |  ✓  |
| Generates alerts             |  ✓  |  ✓  |  ✓  |
| Performs behavioral analysis | N/A | N/A |  ✓  |

#### SIEM and SOAR tools

SIEM is a tool that collects and analyzes log data to monitor critical activities in an organization.
SIEM provides security professionals with a high-level overview of what goes on in their networks.

SIEM process:

1. Collect and aggregate data
2. Normalize data
3. Analyze data

##### SIEM Data Processing Overview

- **Collect & Aggregate**
  SIEM tools ingest event logs (timestamps, IPs, process info, etc.) from diverse sources—firewalls, servers, routers—then consolidate them into a centralized repository. This eliminates the need to manually review each data source.

![alt text](/course6:DetectionAndResponse/resources/SIEM-process.png)

- **Parse**
  Raw log entries are broken into structured fields and values.

  ```
  host = server
  process = sshd
  source_user = nuhara
  source_ip = 218.124.14.105
  source_port = 5023
  ```

- **Normalize**
  Data from different systems (e.g., firewall vs. server logs) is converted into a common format, enabling consistent searching and correlation across all event types.

- **Analyze**
  The SIEM applies detection rules and logic to the normalized data. When a log entry matches a rule, the system generates alerts so security teams can investigate potential threats.

**Security orchestration, automation, adn response (SOAR)** is a collection of applications, tools, and workflows that uses automation to respond to security events.

## Module 2: Network monitoring and analysis

### The importance of network traffic flows

**Network traffic** is the amount of data that moves across a network
**Network data** is the data that's transmitted between devices on a network.

By understanding how data should be flowing across the network, you can develop an understanding of expected network traffic flow. By knowing what's normal, you can easily spot what's abnormal.
We can detect traffic abnormalities through observation to spot indicators of compromise, also known as **IoC**, which are observable evidence that suggests signs of a potential security incident.

For example, **Data exfiltration** is the unauthorized trasmission fo data from a system.
By observing network traffic, we can determine if there's any indicators of compromise, such as large volumes of outbound traffic leaving a host. This is a sign of possible data exfiltration which can be
further investigated.

#### In-Depth Network Monitoring and Baseline Analysis

Effective network security begins with understanding “normal” behavior and then detecting deviations that may indicate compromise. Below is a more detailed breakdown of each phase:

---

1. Establishing a Baseline

- **Data Collection:** Continuously gather metadata on network traffic—source/destination IPs, ports, protocols, byte counts, packet rates, and timestamps—using flow exporters (e.g., NetFlow, sFlow) or switch/router telemetry.
- **Statistical Profiling:** Analyze collected metrics to compute averages, standard deviations, and percentiles for key indicators (e.g., average hourly throughput, peak connection counts).
- **Time‑Window Analysis:** Build profiles for different time blocks (e.g., business hours vs. off‑hours, weekdays vs. weekends) to capture expected variations.
- **Behavioral Patterns:** Identify regular routines such as nightly backups, batch jobs, or routine software updates. These form the “trusted” signature of your environment.

![alt text](/course6:DetectionAndResponse/resources/networks-baseline.png)

2. Continuous Monitoring Techniques

- **Flow Analysis:**

  - Monitor NetFlow/IPFIX records to track the volume and direction of traffic flows.
  - Detect port‑protocol mismatches (e.g., HTTP traffic on unconventional ports) that may signal covert Command & Control (C2) channels.

- **Packet Capture & Deep Inspection:**

  - Use tools like **Wireshark** or **tcpdump** to collect full packet payloads for critical segments.
  - Decrypt TLS sessions (when permitted) for malware signature or data exfiltration detection.

- **Temporal Anomaly Detection:**

  - Alert on significant deviations from baseline thresholds (e.g., a 200% spike in outbound traffic during off‑peak hours).
  - Employ sliding time windows and rolling averages to catch sudden bursts or stealthy low‑and‑slow transfers.

---

3. Indicators of Compromise (IoCs)

- **Unusual Endpoints:** Connections to IPs or domains not seen in baseline inventories.
- **Unexpected Protocols:** Use of peer‑to‑peer or encrypted tunnels instead of standard enterprise services.
- **Volume Anomalies:** Large file transfers or long‑duration sessions inconsistent with normal user behavior.
- **Repetitive Failed Connections:** Repeated authentication or session attempts indicating brute‑force or scanning activity.

---

4. Roles: SOC vs. NOC

- **Security Operations Center (SOC):**

  - Focuses on threat detection, incident investigation, and response.
  - Uses IDS/IPS, SIEM correlation, and threat intelligence feeds to prioritize alerts.

- **Network Operations Center (NOC):**

  - Ensures network uptime, performance, and availability.
  - Monitors link health, hardware status, and service-level metrics.

- **Collaboration:** SOC and NOC share telemetry data—NOC identifies performance anomalies that could stem from attack, SOC validates security context.

---

5.  Tooling & Automation

| Tool Category                    | Examples             | Purpose                                          |
| -------------------------------- | -------------------- | ------------------------------------------------ |
| **Flow Collectors**              | Cisco NetFlow, sFlow | Aggregate metadata for large‑scale flow analysis |
| **Intrusion Detection Systems**  | Snort, Suricata      | Signature and anomaly‑based packet inspection    |
| **Protocol Analyzers**           | Wireshark, tcpdump   | Deep‑dive packet captures and manual triage      |
| **Network Performance Monitors** | SolarWinds, Nagios   | Track latency, packet loss, and interface usage  |
| **SIEM Platforms**               | Splunk, QRadar, ELK  | Correlate logs and flows, automate alerting      |

---

6. Response & Prevention

- **Alert Prioritization:** Leverage severity scoring (e.g., CVSS for threats, anomaly scores) to triage incidents.
- **Automated Playbooks:** Integrate with SOAR tools to execute predefined actions (e.g., block suspicious IPs, quarantine hosts).
- **Continuous Feedback:** Refine baselines and detection rules based on incident post‑mortems and threat intelligence updates.

#### Data Exfiltration Attacks

How an attack performs a data exfiltration attack:

1. Gain initial acces into a network and computer systems: This can be done through a social engineering attack like phishing, which tricks people into disclosing sensitive data
2. Lateral movement or pivoting: This is when they'll spend time exploring the network with the goal of expanding and maintaining their access to other systems on the network.
3. Prepare the data for exfiltration: One way they may do this is by reducing the data size.This helps attackers hide the stolen data and bypass security controls.
4. Exfiltrate the data to their destination of choice: There are many ways to do this. For example, attackers can email the stolen data to themselves using the compromised email account.

Defensive Measures:

1. Prevent attacker access
2. Monitor network activity
3. Protect assets
4. Detect and stop the exfiltration

### Capture and View Network Traffic

A **data packet** is a basic unit of information that travels from one device to another within a network. Detecting network intrusions begins at the packet level. Packets contain three components: the header, the payload, and the footer. Here’s a description of each of these components.

- **Header**: Packets can have several headers depending on the protocols used such as an Ethernet header, an IP header, a TCP header, and more. Headers provide information that’s used to route packets to their destination. This includes information about the source and destination IP addresses, packet length, protocol, packet identification numbers, and more.
  ![alt text](/course6:DetectionAndResponse/resources/datapacket-header.png)
- **Payload**: The data being delivered.
- **Footer**: Most protocols, such as the Internet Protocol (IP), do not use footers. The Ethernet protocol uses footers to provide error-checking information to determine if data has been corrupted.

#### How Packet Sniffers Work

1. Packets must be collected from the network via the **Network Interface Card (NIC)**, which is hardware that connects computers to a network, like a router. NICs receive and transmit network traffic, but by default they only listen to network traffic that’s addressed to them. To capture all network traffic that is sent over the network, a NIC must be switched to a mode that has access to all visible network data packets. A network protocol analyzer must be positioned in an appropriate network segment to access all traffic between different hosts.
2. The network protocol analyzer collects the network traffic in raw binary format. Binary format consists of 0s and 1s and is not as easy for humans to interpret. The network protocol analyzer takes the binary and converts it so that it’s displayed in a human-readable format, so analysts can easily read and understand the information.

## Module 3: Incident investigation and response

### Detection and Analysis Phase of the Lifecycle

**Detection** is the prompt discovery of security events.
**Analysis** is the investigaiton and validation of alerts.

#### Methods of Detection in Incident Response

- **Detection & Analysis Phase:**

  - **Detection** is the rapid identification of potential security events (e.g., via IDS alerts or SIEM correlation).
  - **Analysis** is the investigation and validation of those alerts to confirm true incidents.

- **Challenges:**

  - Tools only see what they’re configured to monitor—misconfigurations or blind spots can allow threats to go unnoticed.

- **Threat Hunting:**

  - A proactive, human‑driven search for hidden threats (like fileless malware) that automated tools may miss.
  - Threat hunters leverage threat intelligence, indicators of compromise/attack, and machine learning to uncover stealthy intrusions before damage occurs.

- **Threat Intelligence:**

  - Contextual, evidence‑based data on attacker TTPs gathered from industry reports, government advisories, and data feeds (IP addresses, domains, hashes).
  - Managed via Threat Intelligence Platforms (TIPs) to prioritize and integrate relevant intelligence into detection workflows.

- **Cyber Deception:**

  - Techniques (e.g., honeypots or fake “client_credit_cards_2022” files) designed to lure attackers into interacting with decoy assets, generating early alerts and insight into malicious behavior.

#### Indicators of Compromise & the Pyramid of Pain

- **IoCs vs. IoAs:**

  - **Indicators of Compromise (IoCs)** are artifacts left behind by completed attacks (e.g., malicious file hashes, IPs, or domain names).

  - **Indicators of Attack (IoAs)** capture ongoing attacker behaviors and methods (e.g., a process making suspicious network connections).

- Detection Value:

  - IoCs help answer who and what after an incident, while IoAs reveal why and how during active attacks.

  - False positives can occur—IoCs may arise from system errors or benign actions, not just malice.

David Bianco’s **Pyramid of Pain** ranks different IoC types by how much “pain” they inflict on attackers when defenders block them. At the base are low‑cost indicators that adversaries can quickly change, while the top tiers represent deep, behavior‑driven artifacts that are costly for attackers to alter:

![alt text](/course6:DetectionAndResponse/resources/pain-pyramid.png)

1. **Hash Values**
   Unique cryptographic fingerprints of malware files. Blocking specific hashes is straightforward but trivial for attackers to bypass by repacking or recompiling code.

2. **IP Addresses**
   Network endpoints used in attacks. Blacklisting an IP stops that address but attackers can shift to new servers or use proxies.

3. **Domain Names**
   URLs that host command‑and‑control or phishing sites. Changing domains requires effort but can be automated with domain‑generation algorithms.

4. **Network Artifacts**
   Protocol or packet characteristics (e.g., uncommon User‑Agent strings) visible on the wire. Altering these may break attacker tooling or introduce instability.

5. **Host Artifacts**
   File names, registry keys, or specific log entries on compromised machines. These require attackers to rewrite payloads and adjust scripts.

6. **Tools**
   The actual utility (e.g., password‑cracking frameworks) used by adversaries. Disrupting toolchains forces attackers to find or develop new tools.

7. **Tactics, Techniques, and Procedures (TTPs)**
   The highest level—attack patterns and workflows defined in frameworks like MITRE ATT\&CK. Mitigating TTPs (for instance, through strong network segmentation or multi‑factor authentication) compels adversaries to fundamentally change their approach, causing maximum friction and “pain.”

By focusing defensive efforts on higher tiers—network and host artifacts, tools, and TTPs—security teams force attackers to redesign their operations rather than simply replace easily modified elements like IPs or file hashes. This elevates the overall cost and complexity of conducting successful attacks.

### Create and Use Documentation

#### Effective Security Documentation

Security documentation—any recorded content used to support investigations, tasks, and communication—delivers three core benefits:

- **Transparency:** Creates audit trails (e.g., chain of custody) that prove compliance with regulations, insurance, and legal requirements.
- **Standardization:** Establishes repeatable procedures (e.g., incident response plans) and aligns teams on policies and frameworks (such as NIST).
- **Clarity:** Presents information in a clear, accessible way so analysts and stakeholders understand actions taken and reasoning behind decisions.

---

#### Best Practices

1. **Know Your Audience**
   Tailor language and detail to readers’ backgrounds—technical depth for SOC teams, high‑level summaries for executives.

2. **Be Concise**
   State the document’s purpose up front. Use brief executive summaries to highlight key findings without overwhelming the reader.

3. **Update Regularly**
   Review and revise documentation after each incident or when new vulnerabilities emerge to keep processes current and effective.

#### Chain of Custody forms

The process of documenting evidence possession and control during an incident lifecycle

### Response and Recovery

**Triage**: The prioritizing of incidents according to their level of importance or urgency.

#### Triage Process in Incident Response

1. **Receive and Assess**

   - **Alert ingestion:** Analysts receive alerts (e.g., from an IDS) and validate them—distinguishing true threats from false positives.
   - **Context gathering:** Review alert history, impacted assets, and known vulnerabilities; evaluate severity.

2. **Assign Priority**

   - **Functional impact:** How the incident disrupts system availability or functionality (e.g., a ransomware lock‑down).
   - **Information impact:** The extent of data confidentiality or integrity loss (e.g., exfiltrated customer records).
   - **Recoverability:** Likelihood and cost of restoring normal operations; low‑recoverability incidents may be deprioritized.

3. **Collect and Analyze**

   - **Evidence collection:** Gather logs, memory snapshots, and other artifacts; consult threat intelligence.
   - **Deep dive:** Perform root‑cause analysis and document findings.
   - **Escalation:** If needed, hand off to senior analysts or managers for advanced techniques or decision‑making.

This structured triage ensures that genuine incidents are rapidly identified, appropriately prioritized, and thoroughly investigated to minimize organizational impact.

### Containment, Eradication, and Recovery phase

**Containment**: The act of limiting and preventing additional damage caused by an incident.
**Eradication**: The complete removal of the incident elemets from all affected systems.
**Recovery**: The process of returning affected systems back to normal operations.

#### Business Continuity Planning (BCP)

When security incidents disrupt operations, a **Business Continuity Plan** ensures critical functions remain available or are rapidly restored, minimizing legal, financial, and reputational damage. Unlike disaster recovery plans (which focus on IT system restoration), BCPs address broad operational continuity.

**Ransomware Impact:**

- Encrypts vital data (e.g., patient records), halting essential services.
- Can threaten national infrastructure, public safety, and economic stability.
- BCPs define how to maintain service delivery even under attack.

**Recovery Strategies & Site Resilience:**
Organizations build resilience by preparing alternative facilities:

- **Hot Site:** A fully mirrored, ready‑to‑use environment that can be activated immediately.
- **Warm Site:** Fully configured but not live; requires final synchronization before use.
- **Cold Site:** Provides basic infrastructure; needs significant setup before operations can resume.

By selecting appropriate recovery sites and embedding them in the BCP, organizations ensure they can continue critical operations despite major disruptions.

### Post-Incident actions

After an incident is contained, eradicated, and systems are restored, the **Post‑Incident Activity** phase turns focus to learning and continuous improvement. This phase consists of three core components:

---

#### 1. Lessons Learned Meetings

- **Timing & Scope:** Convene within two weeks of recovery for major incidents (e.g., ransomware), or aggregate smaller events into periodic reviews.
- **Participants & Roles:** Include all responders—analysts, IT ops, legal, and business stakeholders. Assign a **moderator** to guide discussion and a **scribe** to document key points. Distribute a detailed agenda in advance.
- **Discussion Topics:**

  - **What happened?** Reconstruct the attack vector and timeline.
  - **Detection & Containment:** Evaluate how alerts were generated and acted upon.
  - **Recovery Actions:** Assess the effectiveness and speed of restoration efforts.
  - **Opportunities for Improvement:** Identify procedural gaps, tool limitations, or communication breakdowns.

- **Outcome:** Produce a prioritized list of **actionable recommendations**, such as refining playbook steps, enhancing monitoring rules, or updating escalation criteria.

---

#### 2. Actionable Recommendations

- **Process Enhancements:**

  - Update runbooks to clarify ambiguous steps or reduce response time.
  - Introduce automated triage workflows to cut down manual decision‑making.

- **Technical Controls:**

  - Deploy additional detection signatures or expand coverage in security tools (IDS, EDR).
  - Harden configurations (e.g., restrict admin privileges, enforce multi‑factor authentication).

- **Training & Awareness:**

  - Conduct targeted tabletop exercises based on the incident scenario.
  - Roll out focused workshops for teams on new procedures or tools introduced.

---

#### 3. Final Report

A formal **final report** consolidates all findings and communicates them to varied audiences:

| Section                     | Content                                                                                                                                    |
| --------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------ |
| **Executive Summary**       | A concise overview of the incident’s impact, key findings, and high‑level recommendations (for leadership).                                |
| **Detailed Timeline**       | Timestamped sequence of events—from initial compromise through full recovery—showing detection, containment, and remediation steps.        |
| **Technical Investigation** | In‑depth analysis of artifacts (e.g., log entries, packet captures), root cause determination, and validation of eradication completeness. |
| **Lessons Learned**         | Summary of discussion points from post‑mortem meetings, highlighting strengths and weaknesses in the response.                             |
| **Recommendations**         | A ranked list of short‑term and long‑term actions, with assigned owners and target completion dates.                                       |

---

#### Continuous Improvement

- **Policy & Procedure Updates:** Integrate lessons into the Incident Response Plan and other governance documents.
- **Metrics & Reporting:** Track key performance indicators (e.g., mean time to detect/contain) to measure progress over time.
- **Regular Reviews:** Schedule quarterly drills and annual high‑severity incident reviews to ensure that improvements are retained and processes evolve alongside threat landscapes.

By systematically conducting lessons learned sessions, generating clear reports, and institutionalizing improvements, organizations can strengthen their incident response posture and reduce the impact of future security events.

## Module 4: Network traffic and logs using IDS and SIEM tools

### Overview of Logs

#### Best Practices for Log Collection and Management

- **Purpose & Types of Logs**
  Logs are event records (network, system, application, security, authentication) that help answer the 5 W’s of an incident (who, what, when, where, why). Use verbose logging sparingly to capture additional context only when needed.

- **Selective Logging**
  Avoid “log everything.” Identify critical sources based on your threat model and business requirements, and exclude unnecessary or sensitive data (e.g., PII) to reduce noise, storage costs, and performance impact.

- **Centralized Log Management**
  Collect logs from all devices into a SIEM or dedicated log server. Centralization prevents tampering, simplifies analysis, and provides a unified search interface.

- **Retention & Compliance**
  Implement retention policies aligned with industry regulations (e.g., FISMA, HIPAA, PCI DSS, GLBA, SOX). Ensure logs are stored for the required duration and securely purged thereafter.

- **Log Protection & Integrity**
  Send logs off‑host immediately to a protected central server to guard against deletion or alteration by attackers. Use access controls and checksums to detect unauthorized changes.

By carefully choosing what to log, centralizing and protecting records, and enforcing retention rules, security teams can optimize log analysis, maintain integrity, and meet compliance mandates.

#### Overview of Log File Formats

Security analysts must recognize and parse various log formats to extract meaningful event data. The most common formats include:

---

### JSON

- **Structure:** Key–value pairs, enclosed in `{}` (objects) and `[]` (arrays).
- **Readable & Flexible:** Lightweight, human‑ and machine‑friendly.
- **Example Fields:**

  ```json
  {
    "Alert": "Malware",
    "Alert code": 1090,
    "severity": 10,
    "User": { "id": "1234", "name": "user" }
  }
  ```

---

### Syslog

- **Standard Format:** `<PRI>version timestamp hostname app-name procid [structured-data] message`
- **Transport:** Uses UDP/TCP on ports 514 (plaintext) or 6514 (TLS).
- **Components:**

  - **Header:** Timestamp, host, application, message ID.
  - **Structured Data:** Key–value pairs in `[...]`.
  - **Message:** Free‑form event description.

---

### XML

- **Markup Language:** Data wrapped in `<tags>...</tags>`, supporting nested elements.
- **Attributes:** Added within opening tags for metadata (e.g., `<Data Name="SubjectUserSid">…</Data>`).
- **Hierarchical:** Requires a single root element; children define structured data.

---

### CSV

- **Comma‑Separated:** Each line is a record; fields identified by position.
- **Simplicity:** Easy to produce but relies on external schema to interpret columns.
- **Example Line:**

  ```
  2009-11-24T21:27:09.534255,ALERT,192.168.2.7,1041,10.0.0.50,80,TCP,ALLOWED,...
  ```

---

### CEF (Common Event Format)

- **Pipe‑Delimited Header:**

  ```
  CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extension
  ```

- **Extension:** Optional key–value pairs for additional details.
- **Often Transported via Syslog:** Prepend syslog timestamp and hostname.
- **Example:**

  ```
  Sep 29 08:26:10 host CEF:1|Security|threatmanager|1.0|100|worm stopped|10|src=10.0.0.2 dst=2.1.2.2 spt=1232
  ```

---

By understanding these formats, analysts can quickly locate critical fields (timestamps, IPs, user IDs) and feed logs into SIEMs or custom parsers for efficient security monitoring and investigation.

### Intrusion Detection Sistems (IDS)

**Telemetry**: The collecion and transmission of data for analysis.

---

An **IDS** is a security tool that monitors and analyzes system or network activity to detect signs of malicious behavior and generate alerts. IDS technologies are essential for identifying and responding to threats in real time.

### 📍 **Types of IDS Technologies**

#### 1. **Host-based IDS (HIDS)**

- **Installed directly on endpoints** (computers, servers).
- **Monitors** the **local system activity**, including:

  - File system changes
  - System resource usage
  - User behavior
  - Inbound/outbound traffic

- **Use case:** Detecting suspicious behavior on individual devices (e.g., unauthorized software installation).

#### 2. **Network-based IDS (NIDS)**

- **Deployed on network infrastructure** (e.g., routers, switches, or network monitoring appliances).
- **Monitors** traffic **between multiple devices** on the network.
- **Analyzes**:

  - Packets
  - Network flows
  - Protocol behaviors

- **Use case:** Detecting malicious communication like C2 traffic or scanning activity.

➡️ **Using both HIDS and NIDS** provides **layered visibility**, covering endpoints _and_ the network simultaneously.

---

### 🧠 **Detection Techniques**

Detection techniques define _how_ IDS identifies suspicious or malicious behavior.

#### 1. **Signature-based Detection**

- **How it works:** Matches activity against predefined signatures (patterns of known threats).
- **Sources of signatures:** IPs, hashes, domain names, malware patterns, TTPs.
- **Common use:** Anti-malware software, traditional IDS rules.

#### ✅ Advantages:

- Accurate for **known threats**
- **Low false positives**

#### ❌ Disadvantages:

- Cannot detect **new or unknown threats**
- **Signatures must be updated regularly**
- **Easily evaded** by minor changes in attack patterns

---

#### 2. **Anomaly-based Detection**

- **How it works:** Compares activity to a **baseline** of “normal” behavior.
- Involves:

  - **Training phase:** Learn normal patterns
  - **Detection phase:** Alert when behavior deviates

#### ✅ Advantages:

- Can detect **zero-day threats** and **unusual behaviors**
- Helpful for **behavioral-based** security

#### ❌ Disadvantages:

- **High false positive rate**
- If attacker is present during training, **malicious activity may be normalized**

---

#### 🧩 **Summary Table**

| Feature                 | Signature-Based Detection              | Anomaly-Based Detection                 |
| ----------------------- | -------------------------------------- | --------------------------------------- |
| Detects Known Threats   | ✅ Yes                                 | ❌ Not directly                         |
| Detects Unknown Threats | ❌ No                                  | ✅ Yes                                  |
| False Positives         | 🔽 Low                                 | 🔼 High                                 |
| Requires a Baseline     | ❌ No                                  | ✅ Yes                                  |
| Evasion Resistance      | ❌ Can be evaded by slight changes     | ✅ Harder to evade if baseline is clean |
| Maintenance             | ✅ Requires frequent signature updates | 🔁 Needs training & tuning              |

#### Components of a detection signature

Components of a NIDS rule

1. **Action**

- Determines the action to take if the rule criteria is met
- Alert, pass or reject

2. Header

- Source and destination IP addresses
- Source and destination ports
- Protocols
- Traffic Direction

3. Rule Option

![alt text](/course6:DetectionAndResponse/resources/NIDS.png)

### **Splunk Search Methods**

Splunk uses a powerful query language called **Search Processing Language (SPL)** to retrieve and manipulate log data.

#### **Basic SPL Search**

```spl
index=main fail
```

- `index=main`: Specifies the dataset to search in.
- `fail`: Searches for events containing the term “fail”.

#### **Pipes in SPL**

- Use `|` to chain commands.

```spl
index=main fail | chart count by host
```

- This returns a chart showing the number of "fail" events per host.

#### **Wildcards**

- `fail*` matches all terms starting with “fail” (e.g., “failed”, “failure”).
- Use double quotes (`"login failure"`) for **exact phrase matches**.

#### **Benefits**

- Fast and flexible querying.
- Data transformation and visualization support.
- Powerful filtering and analysis capabilities.

---

### Google SecOps (Chronicle) Search Methods

Chronicle supports two types of searches:

#### 1. **Unified Data Model (UDM) Search**

- **Default and preferred search method**.
- Searches through **normalized and indexed** data.
- Uses structured **UDM fields** like:

  - `metadata.event_type`
  - `metadata.timestamp`
  - `principal.hostname`, `principal.ip`
  - `security_result.action`

#### UDM Search Example:

```udm
metadata.event_type = "USER_LOGIN"
```

- Finds all user login events using the normalized metadata.

#### Key UDM Fields:

- `Entities`: Devices, users, or processes.
- `Event metadata`: Type, time, and context.
- `Network metadata`: Protocols, IPs, ports.
- `Security results`: Outcome like “malware blocked”.

#### 2. **Raw Log Search**

- Searches **unstructured, raw logs**.
- Use when information is **not found** in UDM.
- **Slower** than UDM searches.
- Supports keywords like filenames, hashes, IPs.

**Example:**

Search for “malicious.exe” to locate related raw logs.

---

#### Summary Table

| Feature            | Splunk                           | Google SecOps (Chronicle)         |     |
| ------------------ | -------------------------------- | --------------------------------- | --- |
| Language Used      | SPL (Search Processing Language) | Field-based syntax (UDM)          |     |
| Structured Search  | ✅                               | ✅ (via UDM)                      |     |
| Raw Log Search     | ✅ (via indexes)                 | ✅ (Raw Log Search)               |     |
| Wildcard Support   | ✅ (`*`)                         | ✅ (within supported fields)      |     |
| Pipe Support       | ✅ (\`                           | \` for chaining commands)         | ❌  |
| Best For           | Flexible, customizable search    | Fast, normalized threat hunting   |     |
| Search Performance | Depends on configuration         | UDM is faster than raw log search |     |
