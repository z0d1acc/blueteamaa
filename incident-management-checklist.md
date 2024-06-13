# Incident Management Checklist

### Incident Management Checklist

**Identification Tasks**

_Contents of Tasks:_

* Monitor and analyze security alerts
* Validate the incident
* Assign severity to the incident
* Log initial incident details
* Notify the incident response (IR) team

**Remediation Tasks**

_Contents of Tasks:_

* Contain the incident short-term and long-term
* Eradicate the root cause
* Validate system functionality
* Implement system enhancements
* Notify external entities if needed (such as law enforcement or customers)
* Document actions taken and outcomes

**Other Matters Regarding Tasks**

_Contents:_

* After-action review: Analyze what happened and why, what was effective, and what can be improved.
* Knowledge sharing: Ensure learnings and insights from the incident are shared with relevant stakeholders.
* Updating protocols: Adjust policies and protocols as necessary to prevent repeat incidents.

**Malware Features Checklist**

1. **Behavior Analysis:**
   * Does the malware generate any network traffic?
   * Does it create or modify files?
   * What processes does it run?
   * Is it persistent after a reboot?
2. **Static Properties:**
   * File hash (MD5, SHA-1, SHA-256)
   * File size
   * File type (file signature)
   * File path and name
3. **Infection Vector:**
   * How is it propagated (email, web, removable drives)?
   * Does it exploit any known vulnerabilities?
   * Is it propagated via social engineering?
4. **Payload:**
   * Is it ransomware, spyware, a trojan, a worm, or something else?
   * Does it exfiltrate data?
   * What kinds of data does it target (credentials, personal data, etc.)?
   * Does it have any destructive capabilities?
5. **Evasion Techniques:**
   * Does it have anti-analysis capabilities (like sandbox detection)?
   * Does it employ any obfuscation techniques?
   * Does it have rootkit functionalities to hide its presence?
6. **Command and Control (C2):**
   * Does it communicate with a C2 server?
   * What is the IP address/domain of the C2?
   * What protocols does it use to communicate?
7. **Persistence Mechanism:**
   * How does it ensure it remains on the infected system?
   * Does it create or modify registry entries?
   * Does it create or manipulate scheduled tasks?

[PreviousTactics Tips And Tricks](broken-reference)[NextSecurity Incident-Identification Schema](broken-reference)

Last updated 8 months ago
