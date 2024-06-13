# Wazuh

#### **Cheatsheet** <a href="#cheatsheet" id="cheatsheet"></a>

**Install Wazuh**

* Ensure Wazuh Manager and Agent are installed and configured.

**2. Configure Wazuh Manager**

* Set up manager configurations, including communication and data paths.

**3. Register Wazuh Agents**

* Add and manage agents to communicate with the Wazuh manager.

**4. Implement Wazuh Rules**

* Customize and implement rules for log analysis.

**5. Implement Wazuh Decoders**

* Customize and implement decoders to interpret received logs.

**6. Configure Wazuh Policies**

* Implement policies for compliance and system checks.

**7. Integrate Wazuh with Elastic Stack**

* Set up Wazuh-Elastic Stack integration for visualization and analysis.

**8. Implement Wazuh File Integrity Monitoring**

* Configure syscheck for file integrity monitoring.

**9. Configure Wazuh Alerts**

* Set up alert levels and actions in rules.

**10. Secure Wazuh Manager and Agents**

```
Ensure secure communication and access control.
```

#### Examples for Hardening with Wazuh <a href="#examples-for-hardening-with-wazuh" id="examples-for-hardening-with-wazuh"></a>

**1. Install Wazuh Manager**

Refer to the [Wazuh documentation](https://documentation.wazuh.com/current/installation-guide/index.html) for detailed installation steps.

**2. Register Wazuh Agent**

```
/var/ossec/bin/agent-auth -m [MANAGER_IP]
```

**3. Start Wazuh Agent**

```
systemctl start wazuh-agent
```

**4. Create a Custom Wazuh Rule**

* Navigate to `/var/ossec/etc/rules` and create a custom rule file (e.g., `1000-my_rules.xml`).

**5. Create a Custom Wazuh Decoder**

* Navigate to `/var/ossec/etc/decoders` and create a custom decoder file (e.g., `0005-my_decoders.xml`).

**6. Restart Wazuh Manager**

```
systemctl restart wazuh-manager
```

**7. Enable FIM for a Directory**

Add the following to your `/var/ossec/etc/ossec.conf`:

```
<syscheck>
    <directories check_all="yes">/my/important/directory</directories>
</syscheck>
```

**8. Configure Wazuh Alert Level**

* Edit the rule in `/var/ossec/etc/rules` and set a specific alert level.

**9. Configure Wazuh to Monitor a Log File**

Add the following to your `/var/ossec/etc/ossec.conf`:

```
<localfile>
    <log_format>syslog</log_format>
    <location>/var/log/my_log.log</location>
</localfile>
```

**10. Implement PCI DSS Policy**

* Utilize Wazuh’s built-in PCI DSS compliance capabilities by enabling relevant rules.

**11. Configure Email Alerts**

Add the following to your `/var/ossec/etc/ossec.conf`:

```
<global>
    <email_notification>yes</email_notification>
    <email_to>[YOUR_EMAIL]</email_to>
    <smtp_server>smtp.example.com</smtp_server>
    <email_from>ossec@example.com</email_from>
</global>
```

**12. Implement GDPR Policy**

* Utilize Wazuh’s built-in GDPR compliance capabilities by enabling relevant rules.

**13. Configure Wazuh for Vulnerability Detection**

Add the following to your `/var/ossec/etc/ossec.conf`:

```
<wodle name="vulnerability-detector">
    <enabled>yes</enabled>
    <interval>5h</interval>
    <ignore_time>6h</ignore_time>
    <run_on_start>yes</run_on_start>
    <!-- Add feeds here -->
</wodle>
```

**14. Configure Wazuh for Cloud Security Monitoring**

* Integrate Wazuh with AWS, Azure, or GCP for cloud security monitoring.

**15. Configure Wazuh for Docker Monitoring**

Add the following to your `/var/ossec/etc/ossec.conf`:

```
<wodle name="docker-listener">
    <disabled>no</disabled>
    <interval>10m</interval>
    <run_on_start>yes</run_on_start>
</wodle>
```

**16. Configure Wazuh for Office 365 Monitoring**

* Set up the Office 365 module for monitoring Office 365 activities.

**17. Implement HIPAA Policy**

* Utilize Wazuh’s built-in HIPAA compliance capabilities by enabling relevant rules.

**18. Configure Wazuh for Anomaly and Malware Detection**

* Implement rules and decoders for detecting anomalies and malware activities.

**19. Configure Wazuh for Network IDS**

* Integrate Wazuh with Suricata or Zeek for network intrusion detection.

**20. Configure Wazuh for Endpoint Detection and Response**

* Implement rules, decoders, and policies for monitoring endpoint activities and responding to threats.
