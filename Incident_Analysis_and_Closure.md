# SOC Process for Incident Analysis and Closure

This document provides a detailed explanation of how Security Operations Center (SOC) teams analyze, document, and close security incidents. It includes:

- End-to-end SOC analysis workflow  
- Steps for log analysis  
- Root cause identification methodology  
- Resolution and closure procedures  
- Example ticket closure documentation  

---

# 1. How SOC Teams Analyze, Document, and Close Incidents

SOC teams follow a structured and repeatable process to ensure incidents are handled consistently and thoroughly. The process typically includes:

1. **Alert Review**
2. **Incident Creation**
3. **Detailed Log Analysis**
4. **Root Cause Identification**
5. **Containment & Resolution**
6. **Documentation**
7. **Incident Closure**

Each step is essential for ensuring accuracy, accountability, and continuous improvement.

---

# 2. Detailed Steps for SOC Incident Analysis

## 2.1 Alert Review

- SOC analysts monitor SIEM dashboards, EDR alerts, IDS/IPS events, and user reports.
- Alerts are evaluated for:
  - Severity  
  - Source  
  - Impact  
  - Confidence level  
- L1 analysts determine whether the alert should be escalated to an incident.

---

## 2.2 Incident Creation

If the alert is valid, the SOC creates an incident ticket with:

- Incident ID  
- Summary  
- Description  
- Severity/Priority  
- Affected assets  
- Initial triage notes  
- Assignment group (L1/L2/L3)

This ensures traceability and accountability.

---

# 3. Steps for Log Analysis

Log analysis is the core of SOC investigation. Analysts review logs from multiple sources:

### 3.1 Identify Relevant Log Sources
- SIEM event logs  
- Firewall logs  
- EDR telemetry  
- Authentication logs (AD, Azure AD, Okta)  
- Web server logs  
- DNS logs  
- Email security logs  
- Cloud activity logs  

### 3.2 Correlate Events
Analysts correlate timestamps, IP addresses, user accounts, and event IDs to reconstruct the attack timeline.

### 3.3 Validate Indicators of Compromise (IOCs)
- Hashes  
- Domains  
- URLs  
- IP addresses  
- File names  
- Registry changes  

### 3.4 Determine Scope
- How many systems are affected?  
- Which users were involved?  
- Was lateral movement detected?  
- Is data exfiltration suspected?  

### 3.5 Document Findings
Analysts document:
- What happened  
- When it happened  
- How it happened  
- What logs confirm the activity  

---

# 4. Root Cause Identification

Root cause analysis (RCA) determines **why** the incident occurred.

### 4.1 Identify the Initial Vector
Examples:
- Vulnerable software  
- Weak password  
- Misconfiguration  
- User clicked malicious link  
- Exposed service  

### 4.2 Determine the Attack Path
- Initial access  
- Privilege escalation  
- Lateral movement  
- Persistence  
- Exfiltration  

### 4.3 Validate with Evidence
- Log entries  
- EDR alerts  
- Network traces  
- Forensic artifacts  

### 4.4 Document Root Cause
A clear RCA includes:
- Primary cause  
- Contributing factors  
- Missed detections  
- Control failures  

---

# 5. Resolution Process

## 5.1 Containment
- Isolate affected hosts  
- Block malicious IPs/domains  
- Disable compromised accounts  
- Stop ongoing malicious processes  

## 5.2 Eradication
- Remove malware  
- Patch vulnerabilities  
- Reset credentials  
- Remove persistence mechanisms  

## 5.3 Recovery
- Restore systems from clean backups  
- Re-enable accounts  
- Validate system integrity  
- Monitor for reinfection  

---

# 6. Incident Closure

Incident closure includes:

- Final summary  
- Timeline of events  
- Evidence collected  
- Root cause  
- Actions taken  
- Preventive recommendations  
- Updated detection rules  
- Lessons learned  

Closure ensures the SOC improves continuously.

---

# 7. Example Ticket Closure Documentation

Below is a realistic example of how a SOC analyst documents incident closure.

---

## **Incident ID:** INC-2026-00451  
## **Incident Type:** Unauthorized Login Attempt  
## **Severity:** Medium  
## **Status:** Closed  
## **Assigned To:** SOC Tier 2 Analyst  

---

### **1. Summary**
Multiple failed login attempts were detected on the VPN authentication portal, followed by a successful login from an unusual IP address. Investigation confirmed credential compromise.

---

### **2. Timeline**
| Time (CET) | Event |
|------------|--------|
| 02:14 | SIEM alert triggered for multiple failed logins |
| 02:16 | Successful login from foreign IP |
| 02:18 | L1 escalated to L2 |
| 02:25 | Account disabled |
| 02:40 | Investigation completed |
| 03:00 | Password reset and MFA enforced |
| 03:15 | Incident closed |

---

### **3. Log Analysis Findings**
- Authentication logs show 27 failed attempts from IP `185.22.xxx.xxx`.  
- Successful login occurred from same IP.  
- User confirmed they did not initiate login.  
- No lateral movement detected.  
- No privileged access attempted.

---

### **4. Root Cause**
User reused a password previously exposed in a third‑party breach.  
Attacker used credential stuffing to gain access.

---

### **5. Containment Actions**
- Disabled compromised account  
- Blocked attacker IP at firewall  
- Terminated active sessions  

---

### **6. Eradication Actions**
- Reset user password  
- Forced MFA enrollment  
- Cleared all active tokens  

---

### **7. Recovery Actions**
- Re-enabled account after validation  
- Verified no unauthorized changes  
- Monitored account for 24 hours  

---

### **8. Lessons Learned**
- Improve password policy enforcement  
- Increase monitoring for credential stuffing patterns  
- Conduct user awareness training  

---

### **9. Final Resolution Statement**
Incident resolved. No further malicious activity detected.  
User account secured with MFA and strong password.  
Detection rules updated to alert earlier on similar patterns.

---
