# Assets, Threats, and Vulnerabilities

[**Module 1: Introduction to detection and incident response**](#module-1-introduction-to-detection-and-incident-response)

[**Module 2: Network monitoring and analysis**](#module-2-network-monitoring-and-analysis)

[**Module 3: Incident investigation and response**](#)

[**Module 4: Network traffic and logs using IDS and SIEM tools**](#)

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
