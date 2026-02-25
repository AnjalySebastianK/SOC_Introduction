# Security Incident Types

This document provides detailed explanations of common security incident categories, including short summaries and the required response actions for each type. These categories represent the most frequently encountered threats in SOC environments.

---

## 1. Malware Incidents

### **Summary**
Malware incidents involve malicious software designed to disrupt, damage, or gain unauthorized access to systems. Common malware types include viruses, worms, trojans, ransomware, spyware, and rootkits.

### **Typical Indicators**
- Suspicious processes or services
- Unexpected file encryption or deletion
- Outbound connections to known malicious IPs/domains
- Antivirus/EDR detections
- Unusual CPU, memory, or network usage

### **Required Response Actions**
1. **Detection & Triage**
   - Validate the alert from SIEM/EDR.
   - Identify malware type (ransomware, trojan, etc.).
2. **Containment**
   - Isolate infected hosts from the network.
   - Block malicious domains/IPs.
3. **Eradication**
   - Remove malware using EDR tools or manual cleanup.
   - Patch vulnerabilities exploited by the malware.
4. **Recovery**
   - Restore affected systems from clean backups.
   - Re-enable network access after validation.
5. **Closure**
   - Document root cause.
   - Update detection rules and SOPs.

---

## 2. Phishing Incidents

### **Summary**
Phishing incidents involve attempts to trick users into revealing sensitive information or downloading malicious content. This includes email phishing, spear phishing, smishing, and vishing.

### **Typical Indicators**
- Suspicious email links or attachments
- Credential harvesting pages
- User reports of unusual login prompts
- Multiple failed login attempts after email interaction

### **Required Response Actions**
1. **Detection & Triage**
   - Review the phishing email and headers.
   - Identify targeted users.
2. **Containment**
   - Block sender domain and malicious URLs.
   - Reset credentials if compromised.
3. **Eradication**
   - Remove phishing emails from all inboxes.
   - Scan affected endpoints.
4. **Recovery**
   - Monitor for follow-up attacks.
   - Reinforce MFA and email filtering.
5. **Closure**
   - Conduct user awareness training.
   - Update email security rules.

---

## 3. Insider Threat Incidents

### **Summary**
Insider threats involve malicious or negligent actions by employees, contractors, or partners. These incidents may include data theft, unauthorized access, sabotage, or accidental data exposure.

### **Typical Indicators**
- Accessing data outside normal job role
- Large data transfers or downloads
- Use of unauthorized storage devices
- Suspicious login times or locations

### **Required Response Actions**
1. **Detection & Triage**
   - Validate unusual user behavior.
   - Check access logs and privilege levels.
2. **Containment**
   - Disable user accounts if malicious intent is confirmed.
   - Restrict access to sensitive systems.
3. **Eradication**
   - Remove unauthorized tools or data.
   - Revoke elevated privileges.
4. **Recovery**
   - Restore normal access after investigation.
   - Implement least-privilege controls.
5. **Closure**
   - Conduct HR/legal review.
   - Update insider threat monitoring rules.

---

## 4. Brute Force / Authentication Attacks

### **Summary**
Brute force incidents involve repeated attempts to guess passwords or authentication tokens. Attackers may target VPNs, RDP, SSH, cloud accounts, or web portals.

### **Typical Indicators**
- Multiple failed login attempts from same IP
- Login attempts across many accounts
- Successful login after many failures
- Alerts from IAM, SIEM, or MFA systems

### **Required Response Actions**
1. **Detection & Triage**
   - Identify targeted accounts and source IPs.
   - Check if any attempts succeeded.
2. **Containment**
   - Block attacking IPs.
   - Enforce MFA if not enabled.
3. **Eradication**
   - Reset compromised credentials.
   - Patch exposed authentication services.
4. **Recovery**
   - Monitor for repeated attempts.
   - Strengthen password policies.
5. **Closure**
   - Update brute-force detection rules.
   - Review IAM configurations.

---

## 5. Data Exfiltration Incidents

### **Summary**
Data exfiltration involves unauthorized transfer of sensitive data outside the organization. This may be caused by malware, insiders, or compromised accounts.

### **Typical Indicators**
- Large outbound data transfers
- Unusual uploads to cloud storage
- Data sent to unknown external IPs
- DLP (Data Loss Prevention) alerts

### **Required Response Actions**
1. **Detection & Triage**
   - Validate DLP or SIEM alerts.
   - Identify data type and sensitivity.
2. **Containment**
   - Block outbound connections.
   - Disable compromised accounts.
3. **Eradication**
   - Remove malware or unauthorized tools.
   - Revoke access tokens.
4. **Recovery**
   - Restore normal operations.
   - Monitor for further exfiltration attempts.
5. **Closure**
   - Notify legal/compliance if required.
   - Update DLP rules and monitoring.

---

## 6. Denial of Service (DoS/DDoS)

### **Summary**
DoS/DDoS attacks overwhelm systems or networks with excessive traffic, causing service outages.

### **Typical Indicators**
- Sudden traffic spikes
- Service unavailability
- Network saturation
- Alerts from firewalls or load balancers

### **Required Response Actions**
1. **Detection & Triage**
   - Identify attack vector and target.
2. **Containment**
   - Enable rate limiting.
   - Block malicious IP ranges.
   - Engage ISP for upstream filtering.
3. **Eradication**
   - Remove malicious traffic sources.
4. **Recovery**
   - Restore services and validate stability.
5. **Closure**
   - Implement DDoS protection measures.

---

## Summary Table

| Incident Type      | Summary                                   | Required Response Actions (High-Level)                   |
|--------------------|--------------------------------------------|----------------------------------------------------------|
| Malware            | Malicious software infection               | Isolate → Remove → Patch → Restore                      |
| Phishing           | Social engineering attack                  | Block → Reset creds → Remove emails → Train users       |
| Insider Threat     | Malicious/negligent internal activity      | Investigate → Restrict access → HR/legal review         |
| Brute Force        | Repeated login attempts                    | Block IPs → Reset creds → Enforce MFA                   |
| Data Exfiltration  | Unauthorized data transfer                 | Block → Disable accounts → DLP tuning                   |
| DoS/DDoS           | Service disruption via traffic overload    | Rate limit → Block → ISP filtering                      |

---
