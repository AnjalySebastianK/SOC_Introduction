# Six Incident Response Stages to Real Security Incidents

This document applies the **six stages of the Incident Response Process (IRP)** to five common security incidents:

1. Phishing Attack  
2. DDoS Attack  
3. Ransomware Infection  
4. Data Breach  
5. Brute Force Attack  

Each scenario includes detailed documentation for all six IRP stages:

1. **Preparation**  
2. **Identification**  
3. **Containment**  
4. **Eradication**  
5. **Recovery**  
6. **Lessons Learned**

---

# 1. Phishing Attack

## 1.1 Preparation
- Ensure email filtering and anti-phishing tools are configured.
- Conduct regular user awareness training.
- Maintain updated playbooks for phishing response.
- Enable MFA for all accounts.

## 1.2 Identification
- User reports a suspicious email.
- SOC reviews email headers, links, and attachments.
- SIEM alerts on suspicious login attempts after email interaction.
- Determine if credentials were harvested.

## 1.3 Containment
- Block sender domain and malicious URLs.
- Remove phishing email from all inboxes.
- Disable affected user accounts if compromise is suspected.

## 1.4 Eradication
- Scan affected endpoints for malware.
- Reset compromised credentials.
- Remove unauthorized email forwarding rules.

## 1.5 Recovery
- Re-enable user accounts after validation.
- Monitor for follow-up phishing attempts.
- Strengthen email filtering rules.

## 1.6 Lessons Learned
- Update phishing detection rules.
- Improve user training based on observed patterns.
- Document incident timeline and root cause.

---

# 2. DDoS Attack

## 2.1 Preparation
- Implement rate limiting and traffic filtering.
- Establish agreements with ISP for upstream protection.
- Maintain DDoS response playbooks.

## 2.2 Identification
- Monitoring tools detect traffic spikes.
- Services become slow or unavailable.
- Firewall and load balancer logs show abnormal traffic.

## 2.3 Containment
- Enable DDoS protection mode on firewalls.
- Block malicious IP ranges.
- Redirect traffic through scrubbing centers (ISP support).

## 2.4 Eradication
- Identify and remove malicious traffic sources.
- Apply updated filtering rules.

## 2.5 Recovery
- Gradually restore normal traffic flow.
- Validate service stability.
- Monitor for repeated attacks.

## 2.6 Lessons Learned
- Improve DDoS mitigation strategies.
- Update firewall and WAF rules.
- Document attack vectors and response effectiveness.

---

# 3. Ransomware Infection

## 3.1 Preparation
- Maintain offline backups.
- Deploy EDR with ransomware detection.
- Train users to avoid suspicious downloads.
- Implement least-privilege access.

## 3.2 Identification
- Files become encrypted with unusual extensions.
- Ransom note appears on infected systems.
- EDR alerts on suspicious encryption activity.

## 3.3 Containment
- Immediately isolate infected hosts.
- Disable compromised accounts.
- Block C2 communication domains/IPs.

## 3.4 Eradication
- Remove ransomware binaries and persistence mechanisms.
- Patch exploited vulnerabilities.
- Reset all affected credentials.

## 3.5 Recovery
- Restore systems from clean backups.
- Validate no reinfection.
- Reconnect systems to the network.

## 3.6 Lessons Learned
- Review backup strategy.
- Improve endpoint security controls.
- Update ransomware detection rules.

---

# 4. Data Breach

## 4.1 Preparation
- Implement DLP solutions.
- Encrypt sensitive data.
- Maintain access control policies.
- Conduct regular security audits.

## 4.2 Identification
- DLP alerts on large outbound data transfers.
- Logs show unauthorized access to sensitive files.
- Users report suspicious account activity.

## 4.3 Containment
- Block outbound connections.
- Disable compromised accounts.
- Restrict access to affected systems.

## 4.4 Eradication
- Remove malware or unauthorized tools.
- Revoke compromised API keys or tokens.
- Patch exploited vulnerabilities.

## 4.5 Recovery
- Restore systems to secure state.
- Notify affected users if required by law.
- Monitor for further exfiltration attempts.

## 4.6 Lessons Learned
- Update DLP rules.
- Improve access control and monitoring.
- Conduct a full post-incident review.

---

# 5. Brute Force Attack

## 5.1 Preparation
- Enforce strong password policies.
- Enable MFA for all accounts.
- Configure account lockout thresholds.
- Monitor authentication logs.

## 5.2 Identification
- SIEM alerts on multiple failed login attempts.
- Authentication logs show repeated attempts from the same IP.
- Successful login after many failures indicates compromise.

## 5.3 Containment
- Block attacking IP addresses.
- Disable compromised accounts.
- Increase authentication throttling.

## 5.4 Eradication
- Reset passwords for affected accounts.
- Patch exposed authentication services.
- Remove unauthorized access tokens.

## 5.5 Recovery
- Re-enable accounts after validation.
- Monitor for repeated brute force attempts.
- Strengthen IAM configurations.

## 5.6 Lessons Learned
- Improve brute-force detection rules.
- Enforce MFA organization-wide.
- Update IAM policies and monitoring.

---

# Summary Table

| Incident Type | Identification | Containment | Eradication | Recovery | Lessons Learned |
|---------------|----------------|-------------|-------------|----------|------------------|
| Phishing | Email analysis, user reports | Block sender, remove emails | Reset creds, scan endpoints | Monitor, restore access | Improve training & rules |
| DDoS | Traffic spikes, service outage | Rate limit, block IPs | Remove malicious traffic | Restore services | Improve DDoS strategy |
| Ransomware | Encryption, ransom note | Isolate hosts | Remove malware, patch | Restore backups | Improve EDR & backups |
| Data Breach | DLP alerts, unauthorized access | Block outbound, disable accounts | Remove tools, revoke keys | Restore systems | Improve DLP & access control |
| Brute Force | Failed login attempts | Block IPs, disable accounts | Reset passwords | Monitor IAM | Strengthen MFA & policies |

---
