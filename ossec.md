# OSSEC

#### **Cheatsheet** <a href="#cheatsheet" id="cheatsheet"></a>

**1. Install OSSEC**

* Download OSSEC -> Install OSSEC Server/Agent

**2. Configure OSSEC**

* Edit ossec.conf -> Define configurations

**3. Manage OSSEC Agents**

* Register agents -> Manage agent keys

**4. Customize OSSEC Rules**

* Navigate to rules directory -> Customize or add new rules

**5. Configure OSSEC Alerts**

* Edit ossec.conf -> Define email alerts

**6. Monitor OSSEC Logs**

* Navigate to logs -> Monitor ossec.log

**7. Upgrade OSSEC**

* Download new version -> Upgrade OSSEC

**8. Integrate OSSEC with SIEM**

* Configure OSSEC -> Forward logs to SIEM

**9. Analyze OSSEC Alerts**

* Navigate to alerts directory -> Analyze alerts.log

**10. Secure OSSEC Communication**

```
Configure agent and server -> Validate secure communication
```

#### Examples for Hardening with OSSEC <a href="#examples-for-hardening-with-ossec" id="examples-for-hardening-with-ossec"></a>

**1. Install OSSEC Server**

```
wget https://github.com/ossec/ossec-hids/archive/[VERSION].tar.gz
tar -zxvf [VERSION].tar.gz
cd ossec-hids-[VERSION]
sudo ./install.sh
```

**2. Install OSSEC Agent**

```
# Use the same steps as the server but select agent during installation.
```

**3. Add an OSSEC Agent**

```
sudo /var/ossec/bin/manage_agents
# Follow prompts to add an agent.
```

**4. Extract Agent Key**

```
sudo /var/ossec/bin/manage_agents
# Follow prompts to extract key.
```

**5. Add Agent Key to OSSEC Agent**

```
esudo /var/ossec/bin/manage_agents
# Follow prompts to add key.
```

**6. Restart OSSEC**

```
sudo /var/ossec/bin/ossec-control restart
```

**7. Create a Custom OSSEC Rule**

* Navigate to `/var/ossec/rules` -> Create a custom rule file

**8. Configure OSSEC to Send Email Alerts**

* Edit `/var/ossec/etc/ossec.conf` -> Add email alert settings

**9. Check OSSEC Agent Status**

```
sudo /var/ossec/bin/agent_control -l
```

**10. View OSSEC Logs**

```
ecat /var/ossec/logs/ossec.log
```

**11. Analyze OSSEC Alerts**

```
cat /var/ossec/logs/alerts/alerts.log
```

**12. Upgrade OSSEC Server/Agent**

* Download new version -> Follow upgrade steps

**13. Disable an OSSEC Rule**

* Navigate to `/var/ossec/etc/rules/local_rules.xml` -> Add rule to disable

**14. Configure OSSEC Active Response**

* Edit `/var/ossec/etc/ossec.conf` -> Define active response settings

**15. Test OSSEC Rule**

```
/var/ossec/bin/ossec-logtest
# Enter log entry to test.
```

**16. View OSSEC Agents**

```
sudo /var/ossec/bin/agent_control -lc
```

**17. Remove OSSEC Agent**

```
sudo /var/ossec/bin/manage_agents
# Follow prompts to remove an agent.
```

**18. Configure OSSEC Syscheck**

* Edit `/var/ossec/etc/ossec.conf` -> Define syscheck settings

**19. View OSSEC Statistical Information**

```
sudo /var/ossec/bin/ossec-logtest -s
```

**20. Configure OSSEC to Monitor a File**

* Edit `/var/ossec/etc/ossec.conf` -> Add file to syscheck
