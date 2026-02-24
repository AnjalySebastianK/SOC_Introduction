
# SOC Incident Workflows

This document describes a typical Security Operations Center (SOC) incident workflow from alert detection to incident closure. It explains how incidents are created, assigned, and resolved, and clarifies the roles of L1, L2, and L3 analysts at each stage. A high-level workflow diagram is also included conceptually so it can be implemented as a visual in your documentation.

---

## 1. End-to-end SOC incident workflow overview

A generic SOC incident lifecycle usually follows these stages:

1. **Detection**
2. **Ticket/Incident Creation**
3. **Triage**
4. **Investigation**
5. **Containment & Eradication**
6. **Recovery**
7. **Closure & Lessons Learned**

Each stage involves different responsibilities and may involve different SOC levels (L1, L2, L3).

---

## 2. Step-by-step workflow: from detection to closure

### 2.1 Detection

**Description:**  
A potential security event is detected by one of the following:

- SIEM (e.g., correlation rules, anomaly detection)
- EDR/XDR solutions
- IDS/IPS
- Email security gateways
- User reports (e.g., phishing emails)
- Threat intelligence feeds

**Key actions:**

- The system generates an **alert** with metadata (source, time, severity, indicators).
- The alert is forwarded to the SOC monitoring console and/or ticketing system.

**Primary role:**  
- **L1** monitors dashboards and alert queues.

---

### 2.2 Ticket / Incident creation

**Description:**  
The alert is converted into a **ticket/incident** in the ticketing or case management system (e.g., ServiceNow, Jira, TheHive).

**How incidents are created:**

- **Automatic creation:**
  - SIEM/EDR is integrated with the ticketing system.
  - High/critical alerts automatically generate incidents.
- **Manual creation:**
  - L1 analyst reviews an alert and manually creates an incident if it appears relevant.

**Typical fields:**

- Incident ID
- Title / Summary
- Description
- Severity / Priority
- Category / Subcategory (e.g., Malware, Phishing, Unauthorized Access)
- Source system (SIEM, EDR, user report)
- Affected assets / users
- Initial assignment group (e.g., SOC Tier 1)

**Primary role:**

- **L1** confirms or creates the incident.
- **System** may auto-create based on rules.

---

### 2.3 Triage

**Description:**  
Initial assessment of the incident to determine if it is a **true positive**, **false positive**, or **needs further investigation**.

**Step-by-step:**

1. **Review alert details:**
   - Event logs, source/destination IPs, usernames, timestamps.
2. **Check context:**
   - Asset criticality, user role, known maintenance windows.
3. **Quick validation:**
   - Compare with known false positive patterns.
   - Check if the activity is expected/authorized.
4. **Decision:**
   - If clearly benign → mark as **False Positive** and close.
   - If suspicious or unclear → escalate to investigation.

**Primary role:**

- **L1** performs triage and initial validation.
- **L2** may be consulted for borderline cases.

**Ticket updates:**

- Status: e.g., *New → In Triage → In Progress*
- Notes: triage findings, initial hypothesis.
- Severity may be adjusted based on impact.

---

### 2.4 Investigation

**Description:**  
Deeper analysis to understand the scope, impact, and root cause of the incident.

**Step-by-step:**

1. **Collect additional data:**
   - Endpoint logs, network logs, authentication logs.
   - EDR telemetry, firewall logs, proxy logs.
2. **IOC enrichment:**
   - Check IPs/domains/hashes against threat intel.
   - Use sandboxing, WHOIS, reputation services.
3. **Scope assessment:**
   - Identify affected hosts, users, applications.
   - Determine lateral movement or data exfiltration.
4. **Impact assessment:**
   - Business impact (systems down, data at risk).
   - Regulatory or compliance implications.
5. **Refine classification:**
   - Type of attack (phishing, malware, brute force, insider).
   - Confirm if it is a **true positive**.

**Primary role:**

- **L2** leads investigation.
- **L1** may assist with data collection.
- **L3** joins for complex or high-impact cases.

**Ticket updates:**

- Detailed investigation notes.
- Updated severity and category.
- List of indicators and affected assets.

---

### 2.5 Containment & eradication

**Description:**  
Actions taken to stop the attack and remove the threat.

**Step-by-step:**

1. **Containment:**
   - Isolate compromised hosts from the network.
   - Block malicious IPs/domains at firewall/proxy.
   - Disable compromised accounts.
2. **Eradication:**
   - Remove malware or malicious tools.
   - Revoke malicious access tokens/keys.
   - Apply patches or configuration changes.

**Primary role:**

- **L2** coordinates containment actions.
- **L3** designs complex response strategies.
- **IT/Infrastructure teams** execute some actions (e.g., network isolation).

**Ticket updates:**

- Actions taken (who, what, when).
- Evidence of successful containment/eradication.

---

### 2.6 Recovery

**Description:**  
Restore systems and services to normal operation while ensuring the threat is no longer active.

**Step-by-step:**

1. Restore affected systems from clean backups if needed.
2. Reconnect isolated hosts after validation.
3. Monitor systems for signs of reinfection or residual activity.
4. Validate that security controls are functioning as expected.

**Primary role:**

- **L2** verifies recovery.
- **L3** may validate for major incidents.
- **IT teams** handle system restoration.

**Ticket updates:**

- Recovery steps.
- Verification results.
- Any remaining risks.

---

### 2.7 Closure & lessons learned

**Description:**  
Formal closure of the incident with documentation and improvement actions.

**Step-by-step:**

1. **Document final summary:**
   - What happened, how it was detected, how it was handled.
2. **Root cause analysis:**
   - Underlying cause (vulnerability, misconfiguration, user error).
3. **Lessons learned:**
   - What worked well, what needs improvement.
4. **Improvements:**
   - Update detection rules.
   - Update SOPs and playbooks.
   - Plan awareness training if needed.
5. **Formal closure:**
   - Set status to *Closed*.
   - Use a resolution code (e.g., *True Positive – Contained*).

**Primary role:**

- **L2/L3** document and finalize.
- **Management** may review major incidents.

---

## 3. Roles in each workflow stage (L1, L2, L3)


| Stage                     | L1 Role                              | L2 Role                                      | L3 Role / IR Team                         |
|---------------------------|---------------------------------------|----------------------------------------------|-------------------------------------------|
| Detection                 | Monitor alerts, acknowledge events    | N/A                                          | N/A                                       |
| Ticket Creation           | Create/validate incidents             | N/A                                          | N/A                                       |
| Triage                    | Initial validation, quick checks      | Support for complex triage                   | Rarely involved                           |
| Investigation             | Assist with data collection           | Lead investigation, enrichment, scoping      | Handle complex/critical cases             |
| Containment & Eradication | Execute basic actions (if allowed)    | Coordinate and plan response actions         | Design advanced response strategies       |
| Recovery                  | Monitor post-recovery alerts          | Validate recovery, ensure no reinfection     | Validate for major incidents              |
| Closure & Lessons Learned | Add basic notes                       | Document full incident, root cause, lessons  | Lead post-incident review for major cases |

---

## 4. Workflow
```
                 DETECTION
                     |
                     v
               TICKET CREATION
                     |
                     v
                TRIAGE (L1)
                     |-- False Positive? --> YES --> CLOSE INCIDENT
                                             NO
                                             |
                                             v
                             INVESTIGATION (L2, L3 if needed)
                                             |
                                             v
                           CONTAINMENT & ERADICATION (L2/L3 + IT)
                                             |
                                             v
                                   RECOVERY (L2/L3 + IT)
                                             |
                                             v
              CLOSURE & LESSONS LEARNED (L2/L3, Management for major incidents)

```
---
# 5. Summary
- SOC incident workflows follow a structured lifecycle from **Detection to Closure**.
- **L1** focuses on monitoring and triage, **L2** on investigation and containment, and **L3** on complex response and root cause analysis.
- A clear workflow and role separation ensures consistent handling, proper escalation, and continuous improvement.

---
