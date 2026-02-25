# 10 Common Cyberattacks & Full Incident Response (IRP) Stages

This document explains **10 major cyberattacks** faced by organizations.  
For each attack, the following details are provided:

1. What the attack is  
2. How it occurs  
3. Indicators of compromise (IOCs)  
4. Tools used for detection & mitigation  
5. SOC actions across all **six IRP stages**:
   - Preparation  
   - Identification  
   - Containment  
   - Eradication  
   - Recovery  
   - Lessons Learned  

> **Note:** This list excludes Phishing, DDoS, Ransomware, Data Breach, and Brute Force attacks (already covered earlier).

---

# 1. SQL Injection (SQLi)

## What the attack is
SQL Injection is a web attack where an attacker injects malicious SQL queries into input fields to manipulate backend databases.

## How it occurs
- Poor input validation  
- Unsanitized user input in login forms, search bars, or URL parameters  
- Attackers inject SQL commands like `' OR 1=1 --`  

## Indicators of Compromise
- Unexpected database errors  
- Unauthorized data access  
- Sudden data modification or deletion  
- Web server logs showing suspicious SQL patterns  

## Tools for Detection & Mitigation
- WAF (Cloudflare, ModSecurity)  
- Burp Suite  
- SQLMap  
- SIEM log correlation  
- Secure coding (parameterized queries)  

## SOC Response (IRP Stages)

### Preparation
- Implement secure coding practices  
- Enable WAF rules  
- Conduct regular vulnerability scans  

### Identification
- SIEM alerts on SQL injection patterns  
- Web server logs show suspicious queries  

### Containment
- Block attacker IP  
- Enable strict WAF filtering  
- Disable vulnerable endpoints  

### Eradication
- Patch vulnerable code  
- Fix input validation  
- Remove malicious database entries  

### Recovery
- Restore affected data  
- Validate application functionality  

### Lessons Learned
- Update secure coding guidelines  
- Improve WAF signatures  
- Conduct developer training  

---

# 2. Cross-Site Scripting (XSS)

## What the attack is
XSS allows attackers to inject malicious scripts into web pages viewed by other users.

## How it occurs
- Unsanitized user input  
- Reflected or stored script injection  
- Malicious JavaScript executed in victim browsers  

## Indicators of Compromise
- Unexpected pop-ups  
- Unauthorized session hijacking  
- Browser redirects  
- Suspicious script tags in logs  

## Tools for Detection & Mitigation
- Burp Suite  
- OWASP ZAP  
- WAF  
- CSP (Content Security Policy)  

## SOC Response (IRP Stages)

### Preparation
- Implement input sanitization  
- Enable CSP headers  

### Identification
- Alerts from WAF or SIEM  
- Reports of suspicious browser behavior  

### Containment
- Block malicious payloads  
- Disable vulnerable web components  

### Eradication
- Patch vulnerable code  
- Remove injected scripts  

### Recovery
- Validate application security  
- Re-enable affected services  

### Lessons Learned
- Strengthen input validation  
- Update developer training  

---

# 3. Man-in-the-Middle (MITM)

## What the attack is
MITM attacks intercept communication between two parties to steal or alter data.

## How it occurs
- Rogue Wi-Fi hotspots  
- ARP spoofing  
- SSL stripping  
- DNS poisoning  

## Indicators of Compromise
- Certificate warnings  
- Unexpected network traffic  
- Duplicate IP/MAC addresses  

## Tools for Detection & Mitigation
- Wireshark  
- IDS/IPS  
- SSL/TLS enforcement  
- DNSSEC  

## SOC Response (IRP Stages)

### Preparation
- Enforce HTTPS everywhere  
- Deploy network segmentation  

### Identification
- IDS alerts on ARP spoofing  
- Certificate mismatch logs  

### Containment
- Block rogue devices  
- Reset ARP tables  

### Eradication
- Remove malicious access points  
- Patch network vulnerabilities  

### Recovery
- Restore secure communication channels  

### Lessons Learned
- Improve network monitoring  
- Enforce strict certificate validation  

---

# 4. Supply Chain Attack

## What the attack is
Attackers compromise third-party vendors to infiltrate organizations.

## How it occurs
- Compromised software updates  
- Malicious libraries  
- Vendor credential theft  

## Indicators of Compromise
- Unexpected software behavior  
- Unauthorized outbound connections  
- Vendor-related alerts  

## Tools for Detection & Mitigation
- SBOM (Software Bill of Materials)  
- EDR  
- Threat intelligence feeds  

## SOC Response (IRP Stages)

### Preparation
- Vendor risk assessments  
- Zero-trust architecture  

### Identification
- Alerts tied to vendor systems  
- Suspicious update behavior  

### Containment
- Disable compromised vendor integrations  

### Eradication
- Remove malicious components  
- Patch affected systems  

### Recovery
- Validate vendor updates  
- Restore normal operations  

### Lessons Learned
- Strengthen vendor security requirements  

---

# 5. Zero-Day Exploit

## What the attack is
A zero-day exploit targets unknown vulnerabilities before patches exist.

## How it occurs
- Attackers discover and exploit unpatched flaws  
- Delivered via malware, phishing, or drive-by downloads  

## Indicators of Compromise
- Unexplained crashes  
- Unknown processes  
- EDR behavioral alerts  

## Tools for Detection & Mitigation
- EDR  
- Threat intel  
- Sandboxing  

## SOC Response (IRP Stages)

### Preparation
- Implement EDR with behavioral detection  
- Maintain asset inventory  

### Identification
- Alerts on suspicious behavior  
- Unknown exploit signatures  

### Containment
- Isolate affected systems  

### Eradication
- Apply emergency patches  
- Remove malicious payloads  

### Recovery
- Validate system integrity  

### Lessons Learned
- Improve patch management  
- Enhance threat hunting  

---

# 6. Credential Stuffing

## What the attack is
Attackers use leaked credentials to access accounts.

## How it occurs
- Automated login attempts using stolen username/password pairs  

## Indicators of Compromise
- Multiple login attempts  
- Successful logins from unusual locations  

## Tools for Detection & Mitigation
- IAM logs  
- SIEM  
- MFA enforcement  

## SOC Response (IRP Stages)

### Preparation
- Enforce MFA  
- Monitor login patterns  

### Identification
- SIEM alerts on credential stuffing patterns  

### Containment
- Block offending IPs  
- Lock affected accounts  

### Eradication
- Reset passwords  
- Remove unauthorized sessions  

### Recovery
- Re-enable accounts  

### Lessons Learned
- Improve IAM monitoring  
- Enforce password hygiene  

---

# 7. Insider Data Theft

## What the attack is
Employees steal sensitive data intentionally.

## How it occurs
- USB exfiltration  
- Cloud uploads  
- Unauthorized access  

## Indicators of Compromise
- Large file transfers  
- Access outside job role  

## Tools for Detection & Mitigation
- DLP  
- UEBA  
- SIEM  

## SOC Response (IRP Stages)

### Preparation
- Least privilege  
- DLP policies  

### Identification
- DLP alerts  
- UEBA anomalies  

### Containment
- Disable user accounts  

### Eradication
- Remove unauthorized tools  

### Recovery
- Restore normal access  

### Lessons Learned
- Improve insider threat monitoring  

---

# 8. Watering Hole Attack

## What the attack is
Attackers compromise websites frequently visited by targets.

## How it occurs
- Injecting malware into trusted sites  
- Redirecting users to malicious pages  

## Indicators of Compromise
- Browser exploits  
- Malware infections after visiting known sites  

## Tools for Detection & Mitigation
- Web filtering  
- EDR  
- Threat intel  

## SOC Response (IRP Stages)

### Preparation
- Web filtering policies  
- Patch browsers  

### Identification
- Alerts on drive-by downloads  

### Containment
- Block compromised websites  

### Eradication
- Remove malware  

### Recovery
- Validate endpoints  

### Lessons Learned
- Improve web filtering rules  

---

# 9. DNS Spoofing / Poisoning

## What the attack is
Attackers alter DNS responses to redirect users to malicious sites.

## How it occurs
- DNS cache poisoning  
- Rogue DNS servers  

## Indicators of Compromise
- Redirects to fake websites  
- DNS logs showing mismatched IPs  

## Tools for Detection & Mitigation
- DNSSEC  
- SIEM  
- IDS  

## SOC Response (IRP Stages)

### Preparation
- Implement DNSSEC  
- Harden DNS servers  

### Identification
- Alerts on DNS anomalies  

### Containment
- Flush DNS caches  
- Block rogue DNS servers  

### Eradication
- Patch DNS vulnerabilities  

### Recovery
- Restore DNS integrity  

### Lessons Learned
- Improve DNS monitoring  

---

# 10. Password Spraying

## What the attack is
Attackers try common passwords across many accounts to avoid lockouts.

## How it occurs
- Automated login attempts using weak passwords  

## Indicators of Compromise
- Multiple failed logins across many accounts  
- Successful login with weak password  

## Tools for Detection & Mitigation
- IAM logs  
- SIEM  
- MFA  

## SOC Response (IRP Stages)

### Preparation
- Enforce strong password policies  
- Enable MFA  

### Identification
- SIEM alerts on password spraying patterns  

### Containment
- Block attacker IPs  

### Eradication
- Reset weak passwords  

### Recovery
- Monitor IAM logs  

### Lessons Learned
- Improve password policies  

---
