# SOC Ticketing Tools and Incident Workflow

Security Operations Centers (SOCs) rely heavily on ticketing systems to track, escalate, and close security incidents in a structured, auditable way. This document gives an overview of popular SOC ticketing tools and explains how ticketing systems support the full incident lifecycle—from detection to closure.

---

## 1. Popular SOC ticketing tools

### 1.1 ServiceNow

ServiceNow is an enterprise IT Service Management (ITSM) and workflow platform widely used in large organizations and MSSPs.

- **Primary use in SOC:**  
  **Incident Management**, **Problem Management**, **Change Management**, and **Security Operations** modules.
- **Key strengths for SOC:**
  - **End‑to‑end workflows:** From alert ingestion to incident closure with approvals and SLAs.
  - **CMDB integration:** Link incidents to assets, services, and business impact.
  - **Automation & orchestration:** Playbooks for enrichment, containment, and notifications.
  - **Reporting & dashboards:** SLA tracking, MTTR, incident trends, and analyst performance.
- **Typical SOC use cases:**
  - Ingest alerts from SIEM/SOAR and automatically create tickets.
  - Route incidents to the correct SOC tier based on severity and category.
  - Track regulatory or audit‑relevant incidents with full history.

---

### 1.2 Jira (Jira Service Management / Jira Software)

Jira, especially Jira Service Management, is popular in engineering‑driven environments and smaller SOCs or DevSecOps teams.

- **Primary use in SOC:**  
  Incident tracking, vulnerability management, and coordination with development teams.
- **Key strengths for SOC:**
  - **Flexible workflows:** Custom states (e.g., *New → Triaged → In Progress → Monitoring → Closed*).
  - **Integration with Dev & Sec tools:** Git, CI/CD, vulnerability scanners, SIEM/SOAR via APIs.
  - **Issue linking:** Connect security incidents to bugs, user stories, or change requests.
  - **Agile boards:** Visualize security work alongside development tasks.
- **Typical SOC use cases:**
  - Track security incidents that require code changes or configuration fixes.
  - Manage vulnerability remediation with sprints and backlogs.
  - Use automation rules for assignment, prioritization, and notifications.

---

### 1.3 TheHive

TheHive is an open‑source Security Incident Response Platform (SIRP) designed specifically for SOCs and CSIRTs.

- **Primary use in SOC:**  
  Central platform for **case management**, **alert triage**, and **collaborative investigations**.
- **Key strengths for SOC:**
  - **Security‑focused data model:** Alerts, cases, tasks, observables, and TTPs.
  - **Tight integration with Cortex:** For automated enrichment (WHOIS, VirusTotal, sandboxing, etc.).
  - **Multi‑analyst collaboration:** Tasks, comments, and timelines for each case.
  - **Open APIs:** Easy integration with SIEM, SOAR, and custom tools.
- **Typical SOC use cases:**
  - Convert SIEM alerts into cases with structured tasks.
  - Enrich indicators automatically and document investigation steps.
  - Maintain a detailed audit trail for each incident.

---

### 1.4 Other tools often used in or around SOCs

- **Zendesk / Freshdesk:**  
  - **Use:** Customer‑facing incident communication, especially for MSSPs.  
  - **Strength:** Multi‑channel communication (email, portal, chat) and SLA tracking.

- **RTIR (Request Tracker for Incident Response):**  
  - **Use:** Traditional incident response ticketing, often in CERTs/CSIRTs.  
  - **Strength:** Email‑driven workflows and strong customization.

- **Custom SOAR / SIRP platforms (e.g., Cortex XSOAR, Splunk SOAR):**  
  - **Use:** Combine ticketing with automation and playbooks.  
  - **Strength:** Automated response actions plus case tracking.

---

## 2. How ticketing systems support SOC incident handling

Ticketing systems are the backbone of SOC process discipline. They ensure that every incident is tracked, owned, and resolved in a repeatable way.

### 2.1 Tracking incidents

Ticketing systems provide a **single source of truth** for all security incidents.

- **Unique identifier:**  
  Each incident gets a ticket ID (e.g., `INC0001234`), used in communication and reporting.
- **Standardized fields:**  
  - **Title / Summary**  
  - **Description** (what happened, how it was detected)  
  - **Severity / Priority** (e.g., Critical, High, Medium, Low)  
  - **Category / Subcategory** (e.g., Malware, Phishing, Data Exfiltration)  
  - **Status** (New, In Progress, Contained, Resolved, Closed)  
  - **Owner / Assignee** (SOC Tier 1, Tier 2, IR team, etc.)
- **Audit trail:**  
  Every change (status, comments, assignments) is logged with timestamps and user information.
- **Attachment & evidence management:**  
  Screenshots, logs, PCAPs, and reports can be attached to the ticket.

> **Result:** No incident is “lost in email” or forgotten—everything is visible and traceable.

---

### 2.2 Escalating incidents

Ticketing systems encode the **escalation logic** of the SOC.

- **Tiered support model:**
  - **Tier 1:** Initial triage, basic investigation, false positive filtering.
  - **Tier 2:** Deeper investigation, containment actions, coordination with IT.
  - **Tier 3 / IR / Forensics:** Complex cases, root cause analysis, major incidents.
- **Escalation triggers:**
  - **Severity:** Critical incidents auto‑assign to higher tiers or on‑call IR.
  - **SLA breaches:** If a ticket is not updated within a defined time, it escalates.
  - **Category:** Certain categories (e.g., suspected data breach) always escalate to IR or management.
- **Mechanisms:**
  - **Reassignment:** Change assignee or group (e.g., from *SOC Tier 1* to *SOC Tier 2*).
  - **Linked tickets:** Create problem/change tickets linked to the incident.
  - **Notifications:** Email, chat, or pager alerts to on‑call staff.

> **Result:** High‑risk incidents are handled by the right people at the right time, with clear ownership.

---

### 2.3 Closing incidents

Closing an incident is not just clicking “Close”—it’s a structured step in the lifecycle.

- **Closure conditions:**
  - Threat is contained and eradicated.
  - Business impact is understood and documented.
  - Required changes (patches, config updates) are implemented or scheduled.
  - Stakeholders are informed (e.g., business owner, customer, management).
- **Closure tasks:**
  - **Document root cause** and attack path.
  - **Record lessons learned** and recommended improvements.
  - **Update knowledge base** (playbooks, runbooks, detection rules).
- **Post‑incident review (PIR):**
  - For major incidents, a formal review is held.
  - Ticketing system stores PIR notes, action items, and follow‑up tasks.

> **Result:** Incidents contribute to continuous improvement instead of being one‑off firefights.

---

## 3. Example SOC incident workflow in a ticketing system

Below is a generic workflow that can be implemented in ServiceNow, Jira, TheHive, or similar tools.

### 3.1 High‑level workflow

1. **Detection**
   - **Source:** SIEM alert, EDR alert, user report, threat intel feed.
   - **Action:** Alert is ingested and a ticket is created automatically or manually.

2. **Triage**
   - **SOC Tier 1:** Reviews alert context, checks for obvious false positives.
   - **Decision:**  
     - If false positive → document reason → close ticket.  
     - If true positive or unclear → escalate to investigation.

3. **Investigation**
   - **SOC Tier 2 / IR:**  
     - Collects logs, endpoint data, network traces.  
     - Enriches indicators (IP, domain, hash) via threat intel.  
     - Assesses scope and impact.
   - **Ticket updates:**  
     - Add findings, observables, and hypotheses.  
     - Adjust severity if needed.

4. **Containment & Eradication**
   - **Actions:**  
     - Isolate hosts, block IPs/domains, reset credentials, remove malware.
   - **Ticket updates:**  
     - Document actions, approvals, and timestamps.

5. **Recovery**
   - **Actions:**  
     - Restore services, monitor for re‑infection, validate that controls are effective.
   - **Ticket updates:**  
     - Record recovery steps and verification results.

6. **Closure & Lessons Learned**
   - **Actions:**  
     - Final summary, root cause, and recommendations.  
     - Create follow‑up tasks (e.g., new detection rules, awareness training).
   - **Ticket status:**  
     - Set to *Closed* with a clear resolution code (e.g., *Resolved – True Positive*).

---

## 4. Example diagrams 

### 4.1 Tool comparison overview 


| TOOL                | PRIMARY USE                   | STRENGTHS                                      | TYPICAL SOC SIZE          |
|---------------------|-------------------------------|------------------------------------------------|----------------------------|
| **ServiceNow**      | Enterprise ITSM & SOC Ops <br>Incident Management | - Full workflow automation<br>- CMDB integration<br>- SLA tracking, dashboards | Medium → Large, MSSPs     |
| **Jira (JSM)**      | Incident Tracking<br>DevSecOps Integration | - Highly customizable workflows<br>- Integrates with dev pipelines<br>- Issue linking (bugs, changes) | Small → Medium, Engineering-driven SOCs |
| **TheHive**         | Security Incident Response<br>Case Management | - Security-focused data model<br>- Cortex enrichment automation<br>- Strong collaboration features | Small → Large, CSIRTs & SOCs |
| **Zendesk / Freshdesk** | Customer-facing SOC tickets<br>External communication | - Multi-channel communication<br>- Strong SLA workflows | MSSPs |
| **RTIR**            | CERT/CSIRT Incident Handling  | - Email-driven workflows<br>- Highly customizable | CERT teams, Government/Academia |

---

### 4.2 Incident lifecycle flowchart

```
+------------------+
|    DETECTION     |
+------------------+
          |
          v
+---------------------------+
|    TICKET CREATION        |
| (Auto or Manual)          |
+---------------------------+
          |
          v
+---------------------------+
|          TRIAGE           |
|  - Validate alert         |
|  - Gather basic context   |
+---------------------------+
          |
          |--- Is it a False Positive? ---- YES ---> [CLOSE TICKET]
          |
          NO
          v
+---------------------------+
|      INVESTIGATION        |
|  - Deep analysis          |
|  - IOC enrichment         |
|  - Scope assessment       |
+---------------------------+
          |
          |--- Severity High/Critical? ---- YES ---> [ESCALATE TO TIER 2/IR]
          |
          v
+---------------------------+
|   CONTAINMENT & ACTIONS   |
|  - Isolate host           |
|  - Block indicators       |
|  - Reset credentials      |
+---------------------------+
          |
          v
+---------------------------+
|        RECOVERY           |
|  - Restore services       |
|  - Validate no reinfection|
+---------------------------+
          |
          v
+---------------------------+
|         CLOSURE           |
|  - Root cause analysis    |
|  - Lessons learned        |
|  - Update SOPs/detections |
+---------------------------+
```
---

### 4.3 Escalation path diagram

                 +---------------------------+
                 |   MANAGEMENT / EXECUTIVE  |
                 |   - Business decisions    |
                 |   - Approvals             |
                 |   - Major incident comms  |
                 +---------------------------+
                           ^
                           |  (Escalation for: high impact,
                           |   legal/compliance, executive action)
                           |
                 +---------------------------+
                 |     TIER 3 / IR TEAM      |
                 |   - Advanced forensics    |
                 |   - Root cause analysis   |
                 |   - Major incident lead   |
                 +---------------------------+
                           ^
                           |  (Escalation for: complex cases,
                           |   high severity, deep investigation)
                           |
                 +---------------------------+
                 |         TIER 2            |
                 |   - Investigation         |
                 |   - Containment actions   |
                 |   - IOC enrichment        |
                 +---------------------------+
                           ^
                           |  (Escalation for: unclear alerts,
                           |   medium/high severity, SLA breach)
                           |
                 +---------------------------+
                 |         TIER 1            |
                 |   - Monitoring            |
                 |   - Alert validation      |
                 |   - Initial triage        |
                 +---------------------------+

**Downward arrows can be used to represent**:
 - Feedback
 - Guidance
 - Instructions
 - Communication back to lower tiers

---

