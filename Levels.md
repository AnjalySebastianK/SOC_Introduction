# SOC OPERATING LEVELS & PROCEDURES
A detailed guide to understanding how L1, L2, and L3 analysts operate within a Security Operations Center (SOC), including workflows, responsibilities, and coordination.

---

#  A. L1 STANDARD PROCEDURES (Monitoring & Triage)

## **Role Overview**
L1 analysts are the SOC’s first line of defense. They continuously monitor alerts, validate suspicious activity, and escalate real incidents.

## **Core Responsibilities**
- Monitor SIEM dashboards and alert queues.
- Validate alerts (true positive vs. false positive).
- Perform initial triage and gather basic context.
- Follow SOPs for classification and escalation.
- Document findings in the ticketing system.
- Communicate with L2 when escalation is required.

## **Standard L1 Procedures**
1. **Alert Monitoring**
   - Check SIEM dashboards (e.g., Splunk, QRadar, Sentinel).
   - Prioritize alerts based on severity.

2. **Initial Validation**
   - Check source/destination IP reputation.
   - Review user activity logs.
   - Verify if the alert matches known benign patterns.

3. **Triage**
   - Classify alert: informational, suspicious, or malicious.
   - Add notes, screenshots, and log snippets.

4. **Containment (Basic)**
   - Block IPs/domains (if allowed by SOP).
   - Disable compromised accounts (if permitted).

5. **Escalation**
   - Escalate to L2 if:
     - Incident is confirmed malicious.
     - Requires deeper investigation.
     - Involves critical assets.

6. **Documentation**
   - Update ticket with all steps taken.
   - Attach evidence and triage summary.

---

#  B. L2 STANDARD PROCEDURES (Investigation & Response)

## **Role Overview**
L2 analysts perform deeper investigations, correlate events, and execute containment and remediation actions.

## **Core Responsibilities**
- Investigate escalated incidents.
- Perform log correlation and root‑cause analysis.
- Execute containment and remediation actions.
- Coordinate with IT teams for system recovery.
- Prepare detailed incident reports.
- Improve detection rules and SOPs.

## **Standard L2 Procedures**
1. **Incident Review**
   - Analyze L1 notes and evidence.
   - Validate escalation accuracy.

2. **Deep Investigation**
   - Correlate logs across SIEM, EDR, firewall, proxy, AD.
   - Identify attacker behavior (MITRE ATT&CK mapping).
   - Determine scope and impact.

3. **Containment**
   - Isolate infected hosts.
   - Block malicious IPs/domains.
   - Reset compromised credentials.
   - Apply firewall/EDR rules.

4. **Eradication**
   - Remove malware or persistence mechanisms.
   - Patch vulnerabilities.
   - Clean registry entries or malicious scripts.

5. **Recovery**
   - Restore systems to normal operation.
   - Monitor for reinfection.

6. **Reporting**
   - Write detailed incident reports.
   - Provide recommendations to improve defenses.

---

#  C. L3 STANDARD PROCEDURES (Threat Hunting & Advanced Analysis)

## **Role Overview**
L3 analysts are senior experts who handle complex threats, perform forensics, and proactively hunt for unknown attacks.

## **Core Responsibilities**
- Conduct threat hunting and advanced investigations.
- Perform malware analysis and digital forensics.
- Develop SIEM detection rules and use cases.
- Analyze threat intelligence and emerging threats.
- Support incident response for major breaches.
- Mentor L1 and L2 analysts.

## **Standard L3 Procedures**
1. **Advanced Investigation**
   - Reverse‑engineer malware samples.
   - Analyze memory dumps and disk images.
   - Perform deep forensic analysis.

2. **Threat Hunting**
   - Search for hidden or undetected threats.
   - Identify anomalies using behavioral analytics.
   - Create hypotheses and test them with data.

3. **Detection Engineering**
   - Build SIEM correlation rules.
   - Tune alerts to reduce false positives.
   - Develop YARA/Sigma rules.

4. **Threat Intelligence Integration**
   - Analyze IOCs, TTPs, and threat actor profiles.
   - Update detection mechanisms accordingly.

5. **Major Incident Support**
   - Lead response for critical or complex incidents.
   - Coordinate with external teams (IR firms, CERTs).

6. **SOC Improvement**
   - Update SOPs.
   - Train L1/L2 analysts.
   - Conduct tabletop exercises.

---

#  D. COORDINATION BETWEEN L1, L2, AND L3

## **How They Work Together**
The SOC operates like a tiered escalation system:

| SOC Level | Primary Focus | Escalates To | Typical Tasks |
|----------|----------------|--------------|----------------|
| **L1** | Monitoring & triage | L2 | Validate alerts, classify incidents |
| **L2** | Investigation & response | L3 | Deep analysis, containment, remediation |
| **L3** | Threat hunting & advanced forensics | — | Complex threats, detection engineering |

---

# E. SOC ESCALATION FLOWCHART (ASCII)

```

                +----------------------+
                |   SIEM Generates     |
                |       Alert          |
                +----------+-----------+
                           |
                           v
                +----------------------+
                |   L1 Analyst Triage  |
                |  - Validate alert    |
                |  - Gather context    |
                +----------+-----------+
                           |
            +--------------+--------------+
            |                             |
            v                             v
   +------------------+          +----------------------+
   | False Positive   |          | True Positive        |
   |  Ticket Closed   |          |   Escalate to L2     |
   +------------------+          +----------+-----------+
                                           |
                                           v
                              +---------------------------+
                              |     L2 Investigation      |
                              |  - Log correlation        |
                              |  - Scope analysis         |
                              |  - Containment actions    |
                              +-----------+---------------+
                                          |
                                          v
                              +---------------------------+
                              |   L3 Advanced Analysis    |
                              |  - Forensics              |
                              |  - Threat hunting         |
                              |  - Malware analysis       |
                              +-----------+---------------+
                                          |
                                          v
                              +---------------------------+
                              |     Incident Resolved     |
                              |   Documentation & Lessons |
                              +---------------------------+
```

---

#  SUMMARY OF COORDINATION

### **L1 → L2**
- L1 escalates validated incidents.
- Provides initial triage notes and evidence.
- L2 takes over for deeper investigation.

### **L2 → L3**
- L2 escalates complex, high‑severity, or unclear incidents.
- L3 performs advanced forensics or threat hunting.

### **L3 → SOC Improvements**
- L3 updates detection rules.
- Improves SOPs.
- Trains L1 and L2 analysts.

### **Feedback Loop**
- L3 insights → better L2 investigations.
- L2 findings → better L1 triage.
- L1 patterns → help L3 refine detection rules.

---
