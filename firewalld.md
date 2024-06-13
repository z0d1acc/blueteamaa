# Firewalld

#### **Cheatsheet** <a href="#cheatsheet" id="cheatsheet"></a>

**1. Install Firewalld**

* Ensure Firewalld is installed and running on your system.

**2. Manage Firewalld Service**

* Start, enable, stop, or disable the Firewalld service.

**3. Configure Zones**

* Define and manage zones to control the trust level of network connections.

**4. Manage Services**

* Allow, deny, or customize services in zones.

**5. Manage Ports**

* Open or close specific ports in zones.

**6. Manage Interfaces**

* Assign network interfaces to zones.

**7. Manage Sources**

* Assign specific IP addresses or subnets to zones.

**8. Manage ICMP Blocks**

* Allow or deny ICMP messages in zones.

**9. Manage Masquerading and Port Forwarding**

* Configure NAT and port forwarding.

**10. Manage Rich Rules**

```
Use rich rules for more detailed control over traffic.
```

**20 Real Examples for Hardening with Firewalld**

**1. Install Firewalld**

```
sudo yum install firewalld
```

**2. Start and Enable Firewalld**

```
sudo systemctl start firewalld
sudo systemctl enable firewalld
```

**3. Get Active Zone**

```
sudo firewall-cmd --get-active-zones
```

**4. Change Default Zone**sudo firewall-cmd --set-default-zone=home

**5. Add Service to Zone**

```
sudo firewall-cmd --zone=public --add-service=http --permanent
```

**6. Remove Service from Zone**

```
sudo firewall-cmd --zone=public --remove-service=http --permanent
```

**7. Add Port to Zone**

```
sudo firewall-cmd --zone=public --add-port=8080/tcp --permanent
```

**8. Remove Port from Zone**

```
sudo firewall-cmd --zone=public --remove-port=8080/tcp --permanent
```

**9. Reload Firewalld**

```
sudo firewall-cmd --reload
```

**10. Add Interface to Zone**

```
sudo firewall-cmd --zone=public --add-interface=eth0 --permanent
```

**11. Add Source to Zone**

```
sudo firewall-cmd --zone=public --add-source=192.168.1.0/24 --permanent
```

**12. Enable Masquerading**

```
sudo firewall-cmd --zone=public --add-masquerade --permanent
```

**13. Add Forward Port**

```
sudo firewall-cmd --zone=public --add-forward-port=port=80:proto=tcp:toport=8080 --permanent
```

**14. Add ICMP Block**

```
sudo firewall-cmd --zone=public --add-icmp-block=echo-request --permanent
```

**15. Create Custom Service**

* Define a custom service XML file and place it in `/etc/firewalld/services/`.

**16. Add Custom Service to Zone**

```
sudo firewall-cmd --zone=public --add-service=custom-service --permanent
```

**17. Add Rich Rule**

```
sudo firewall-cmd --zone=public --add-rich-rule='rule family="ipv4" source address="192.168.1.100" accept' --permanent
```

**18. Remove Rich Rule**

```
sudo firewall-cmd --zone=public --remove-rich-rule='rule family="ipv4" source address="192.168.1.100" accept' --permanent
```

**19. Query Service in Zone**

```
sudo firewall-cmd --zone=public --query-service=http
```

**20. List All Configurations**

```
sudo firewall-cmd --list-all-zones
```
