# Ansible

#### Cheatsheet <a href="#cheatsheet" id="cheatsheet"></a>

**1. Install Ansible**

* Download and install Ansible on the control node.

**2. Configure Ansible Hosts**

* Define hosts and groups in the Ansible inventory.

**3. Write Playbooks**

* Create Ansible playbooks to define the desired state of systems.

**4. Use Ansible Roles**

* Utilize roles for organizing and reusing playbooks.

**5. Run Ansible Playbooks**

* Execute playbooks to apply configurations to hosts.

**6. Use Ansible Galaxy**

* Leverage Ansible Galaxy to use pre-built roles.

**7. Secure Ansible Vault**

* Use Ansible Vault to secure sensitive data.

**8. Optimize Ansible Configurations**

* Tweak ansible.cfg for performance and behavior.

**9. Utilize Ansible Modules**

* Use modules to define the desired state in playbooks.

**10. Implement Ansible Facts**

```
diffCopy code- Use gathered facts for making informed decisions in playbooks.
```

#### Examples for Hardening with Ansible <a href="#examples-for-hardening-with-ansible" id="examples-for-hardening-with-ansible"></a>

**1. Install Ansible**

```
sudo apt update
sudo apt install ansible
```

**2. Add Hosts to Ansible Inventory**

```
[webservers]
192.168.1.10
192.168.1.11
```

**3. Simple Ansible Playbook to Update Systems**

```
---
- hosts: webservers
  become: yes
  tasks:
    - name: Ensure all packages are updated
      apt:
        update_cache: yes
        upgrade: safe
```

**4. Run Ansible Playbook**

```
ansible-playbook -i hosts update_system.yml
```

**5. Use Ansible Role from Galaxy**

```
ansible-galaxy install dev-sec.os-hardening
```

**6. Use Ansible Vault to Encrypt Data**

```
ansible-vault create secret.yml
```

**7. Use Encrypted Data in Playbook**

```
---
- hosts: webservers
  become: yes
  vars_files:
    - secret.yml
  tasks:
    - name: Add user
      user:
        name: "{{ username }}"
        password: "{{ password }}"
```

**8. Run Playbook with Vault Password**

```
ansible-playbook --ask-vault-pass -i hosts add_user.yml
```

**9. Use Ansible Facts in Playbook**

```
---
- hosts: webservers
  tasks:
    - name: Display OS
      debug:
        var: ansible_distribution
```

**10. Install and Start Apache using Ansible**

```
---
- hosts: webservers
  become: yes
  tasks:
    - name: Ensure Apache is installed
      apt:
        name: apache2
        state: present
    - name: Ensure Apache is running
      service:
        name: apache2
        state: started
```

**11. Create a User with Ansible**

```
---
- hosts: webservers
  become: yes
  tasks:
    - name: Ensure user 'john' exists
      user:
        name: john
        state: present
```

**12. Disable Unused Service**

```
---
- hosts: webservers
  become: yes
  tasks:
    - name: Ensure telnet is stopped and disabled
      service:
        name: telnet
        state: stopped
        enabled: no
```

**13. Configure SSH Hardening**

```
---
- hosts: webservers
  become: yes
  tasks:
    - name: Ensure only SSH protocol 2 is used
      lineinfile:
        path: /etc/ssh/sshd_config
        regex: '^Protocol'
        line: 'Protocol 2'
```

**14. Set Up a Firewall Rule**

```
---
- hosts: webservers
  become: yes
  tasks:
    - name: Allow only SSH and HTTP through the firewall
      ufw:
        rule: allow
        name: "{{ item }}"
      loop:
        - ssh
        - http
```

**15. Ensure a Package is Removed**

```
---
- hosts: webservers
  become: yes
  tasks:
    - name: Ensure 'telnet' is removed
      apt:
        name: telnet
        state: absent
```

**16. Configure Password Authentication**

```
---
- hosts: webservers
  become: yes
  tasks:
    - name: Disable password authentication
      lineinfile:
        path: /etc/ssh/sshd_config
        regex: '^PasswordAuthentication'
        line: 'PasswordAuthentication no'
```

**17. Ensure NTP is Configured**

```
---
- hosts: webservers
  become: yes
  tasks:
    - name: Ensure NTP is installed
      apt:
        name: ntp
        state: present
```

**18. Configure Kernel Parameters**

```
---
- hosts: webservers
  become: yes
  tasks:
    - name: Ensure IP forwarding is disabled
      sysctl:
        name: net.ipv4.ip_forward
        value: '0'
        state: present
```

**19. Ensure a Service is Running**

```
---
- hosts: webservers
  become: yes
  tasks:
    - name: Ensure Apache is running
      service:
        name: apache2
        state: started
```

**20. Apply Security Patches**

```
---
- hosts: webservers
  become: yes
  tasks:
    - name: Ensure all packages are updated
      apt:
        upgrade: dist
        
```
