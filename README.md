SOC Investigation – Classic SQL Injection Attack Detection
📌 **Objective**
Detect, investigate, and document a simulated SQL Injection (SQLi) attack against a web application, following SOC analysis workflows.

🛡 **Overview of SQL Injection (SQLi)**
Definition: SQLi occurs when unsanitized user input is embedded directly into SQL queries, allowing attackers to manipulate database queries.

In simpler terms:
It’s like ordering food at a restaurant and, in the same order, slipping in, “Oh, and give me the combination to the safe.” If the waiter doesn’t double-check and block that part of the request, the attacker walks away with much more than they should.

🧰 **Tools & Techniques Used**
Monitoring: Reviewed alerts in a SOC-style dashboard to identify suspicious activity.

Log Management: Analyzed HTTP traffic and system logs to spot SQL patterns.

Case Management: Claimed alert, opened a case, and documented steps using structured workflows.

Endpoint Security: Checked affected systems for signs of compromise or malware.

Email Security: Investigated potential phishing or coordination attempts.

Threat Intelligence: Queried attacker IPs in AbuseIPDB and VirusTotal for reputation data.

🔍 **Investigation Workflow**
**Alert Claim & Case Initiation**

Claimed the SQLi alert in the SOC system and initiated the playbook to ensure a structured investigation and documentation process.

**Log Analysis**

Found a request containing a suspicious SQLi payload.

Noted a change in response size compared to other attempts, marking the start of the exploitation phase.

Determined as malicious activity requiring deeper review.

**Source IP Investigation**

Checked the attacker’s IP using AbuseIPDB and VirusTotal, confirming prior malicious activity reports.

**Attack Classification**

Classified as Classic (In-band) SQL Injection: The attacker received an immediate HTTP 200 (OK) response, providing real-time feedback — a hallmark of this SQLi type.

**Additional Checks & Success Evaluation**

Reviewed related email records — no evidence of pre-attack coordination found.

Checked the targeted endpoint — no unauthorized services or executed commands detected.

Concluded the SQLi attempt was unsuccessful.

**Documentation & Closure**

Added artifacts (payload samples, decoded data, log snippets) to the case.

Recorded investigation notes and closed with "Attempted SQLi – No Compromise".

🧠 **Key Skills Demonstrated**
Threat detection & log analysis

HTTP traffic analysis

Threat intelligence gathering

SOC workflow adherence (alert handling, playbook execution, case documentation)

✅ **Outcome**
The SQLi attempt was detected, classified, and investigated thoroughly. No compromise occurred, and findings were documented for potential use in refining detection rules, audits, and future analyst training.

