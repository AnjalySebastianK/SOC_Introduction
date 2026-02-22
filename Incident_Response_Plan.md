# INCIDENT RESPONSE PLAN (IRP) — DETAILED DOCUMENTATION
A structured guide explaining the six core stages of the Incident Response Plan (IRP), including definitions, workflows, and real-world SOC examples.

---

#  A. SIX STAGES OF INCIDENT RESPONSE PLAN (IRP)

1. **Preparation**
2. **Identification**
3. **Containment**
4. **Eradication**
5. **Recovery**
6. **Lessons Learned**

These stages form the backbone of any SOC’s incident-handling process.

---

#  B. DETAILED EXPLANATION OF EACH STAGE

## 1. Preparation
The foundation of the entire IRP. This stage ensures the organization is ready to detect and respond to incidents.

### Key Activities:
- Develop and maintain IRP, SOPs, and playbooks.
- Configure SIEM, EDR, firewalls, and monitoring tools.
- Train SOC analysts on detection and response procedures.
- Ensure logging, alerting, and visibility across systems.
- Conduct tabletop exercises and simulations.

### Goal:
Build a strong security posture and reduce response time.

---

## 2. Identification
Detecting and confirming whether an event is a security incident.

### Key Activities:
- Monitor SIEM alerts, EDR events, and logs.
- Validate alerts (true positive vs. false positive).
- Determine the type, scope, and severity of the incident.
- Document initial findings.

### Goal:
Accurately identify real incidents as early as possible.

---

## 3. Containment
Limit the spread and impact of the incident.

### Types of Containment:
- **Short-term containment:** Immediate actions to stop ongoing damage.
- **Long-term containment:** More permanent measures to prevent recurrence.

### Key Activities:
- Isolate infected hosts.
- Block malicious IPs/domains.
- Disable compromised accounts.
- Apply temporary firewall rules.

### Goal:
Prevent further damage while preparing for eradication.

---

## 4. Eradication
Remove the threat completely from the environment.

### Key Activities:
- Delete malware, scripts, or malicious files.
- Patch vulnerabilities exploited by attackers.
- Remove persistence mechanisms.
- Clean registry entries or scheduled tasks.

### Goal:
Ensure the threat actor no longer has access.

---

## 5. Recovery
Restore systems to normal operation safely.

### Key Activities:
- Rebuild or restore systems from clean backups.
- Re-enable accounts after verification.
- Monitor systems for signs of reinfection.
- Validate system integrity.

### Goal:
Return to business-as-usual without reintroducing the threat.

---

## 6. Lessons Learned
Analyze the incident to improve future response.

### Key Activities:
- Conduct a post-incident review meeting.
- Document root cause, timeline, and response actions.
- Update SOPs, detection rules, and playbooks.
- Train SOC staff based on findings.

### Goal:
Strengthen the organization’s security posture and prevent similar incidents.

---

#  C. INCIDENT RESPONSE PLAN FLOWCHART (ASCII)
```
             +----------------------+
             |     Preparation      |
             |  Tools, training,    |
             |  policies, playbooks |
             +----------+-----------+
                        |
                        v
             +----------------------+
             |    Identification    |
             | Detect & confirm     |
             | security incidents   |
             +----------+-----------+
                        |
                        v
             +----------------------+
             |     Containment      |
             | Short-term & long-   |
             | term isolation       |
             +----------+-----------+
                        |
                        v
             +----------------------+
             |     Eradication      |
             | Remove malware, fix  |
             | vulnerabilities       |
             +----------+-----------+
                        |
                        v
             +----------------------+
             |      Recovery        |
             | Restore systems &    |
             | monitor stability    |
             +----------+-----------+
                        |
                        v
             +----------------------+
             |   Lessons Learned    |
             | Review, improve,     |
             | update procedures    |
             +----------------------+
```

---

#  D. REAL-WORLD SOC EXAMPLES FOR EACH STAGE

## **1. Preparation — Example**
A SOC configures Microsoft Sentinel SIEM, sets up alert rules for brute-force attacks, and trains analysts on how to triage authentication anomalies.

## **2. Identification — Example**
L1 analyst receives an alert:  
“Multiple failed login attempts from an unusual IP.”  
After checking logs, the analyst confirms it’s a brute-force attack → escalates to L2.

## **3. Containment — Example**
L2 analyst blocks the attacker’s IP address and disables the compromised user account to stop further unauthorized access.

## **4. Eradication — Example**
L2/L3 analysts:
- Remove malicious scripts from the compromised host.
- Patch the vulnerable RDP service exploited by the attacker.
- Remove persistence mechanisms (scheduled tasks, registry keys).

## **5. Recovery — Example**
The IT team rebuilds the compromised server from a clean backup and re-enables the user account after resetting credentials.

## **6. Lessons Learned — Example**
The SOC conducts a review and discovers:
- Weak password policy enabled the attack.
- No MFA was enforced.

Actions taken:
- Implement MFA.
- Update password policy.
- Add new SIEM detection rules for brute-force attempts.

---
