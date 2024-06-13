# Protect Defend

**Protection and Defense** Windows

**Disabling or Stopping Services**

List of stopped or disabled services:

```
C:\> sc query
C:\> sc config "<SERVICE_NAME>" start= disabled
C:\> sc stop "<SERVICE_NAME>"
C:\> wmic service where name='<SERVICE_NAME>' call ChangeStartmode Disabled
```

**Host Firewall**

View all rules:

```
C:\> netsh advfirewall firewall show rule name=all
```

Enable or disable the firewall:

```
C:\> netsh advfirewall set currentprofile state on
C:\> netsh advfirewall set currentprofile firewallpolicy blockinboundalways,allowoutbound
C:\> netsh advfirewall set publicprofile state on
C:\> netsh advfirewall set privateprofile state on
C:\> netsh advfirewall set domainprofile state on
C:\> netsh advfirewall set allprofile state on
C:\> netsh advfirewall set allprof ile state off
```

**Setting a New Rule for the Firewall:**

```
C:\> netsh advfirewall firewall add rule name="Open Port 80" dir=in action=allow protocol=TCP localport=80

C:\> netsh advfirewall firewall add rule name="My Application" dir=in action=allow program="C:\MyApp\MyApp.exe" enable=yes

C:\> netsh advfirewall firewall add rule name="My Application" dir=in action=allow program="C:\MyApp\MyApp.exe" enable=yes remoteip=157.60.0.1,172.16.0.0/16,LocalSubnet profile=domain

C:\> netsh advfirewall firewall add rule name="My Application" dir=in action=allow program="C:\MyApp\MyApp.exe" enable=yes remoteip=157.60.0.1,172.16.0.0/16,LocalSubnet profile=private

C:\> netsh advfirewall firewall delete rule name=rule name program="C:\MyApp\MyApp.exe"

C:\> netsh advfirewall firewall delete rule name=rule name protocol=udp localport=500

C:\> netsh advfirewall firewall set rule group="remote desktop" new enable=Yes profile=domain

C:\> netsh advfirewall firewall set rule group="remote desktop" new enable=No profile=public
```

**Setting the Location of Reports:**

```
C:\> netsh advfirewall set currentprofile logging C:\<LOCATION>\<FILE_NAME>
```

**Setting and Changing the Location of Firewall Reports:**

```
C:\> more %systemroot%\system32\LogFiles\Firewall\pfirewall.log

C:\> netsh advfirewall set allprofile logging maxfilesize 4096

C:\> netsh advfirewall set allprofile logging droppedconnections enable

C:\> netsh advfirewall set allprofile logging allowedconnections enable
```

**Viewing Firewall Reports:**

```
PS C:\> Get-Content $env:systemroot\system32\LogFiles\Firewall\pfirewall.log
```

**Passwords**

* **Changing the Password:**

```
C:\> net user <USER_NAME> * /domain
C:\> net user <USER_NAME> <NEW_PASSWORD>
```

*

```
C:\> pspasswd.exe \\<IP_ADDRESS_or_NAME_OF_REMOTE_COMPUTER> -u <REMOTE_USER_NAME> -p <NEW_PASSWORD>
```

```
PS C:\> pspasswd.exe \\<IP_ADDRESS_or_NAME_OF_REMOTE_COMPUTER>
```

**Host Files**

* **Resetting DNS:**
* **Resetting NetBios Cache:**
* **Adding Malicious Domain and Redirecting it to Localhost:**

```
C:\> echo 127.0.0.1 <MALICIOUS_DOMAIN> >> C:\Windows\System32\drivers\etc\hosts
```

* **Checking Host Files by Pinging 127.0.0.1:**

```
C:\> ping <MALICIOUS_DOMAIN> -n 1
```

**Whitelist**

* **Creating and Using a Proxy Auto Config (PAC) File for Suspicious URLs and IPs:**

```
function FindProxyForURL(url, host) {
    // Send bad DNS name to the proxy
    if (dnsDomainIs(host, ".badsite.com"))
        return "PROXY http://127.0.0.1:8080";
    // Send bad IPs to the proxy
    if (isInNet(myIpAddress(), "222.222.222.222", "255.255.255.0"))
        return "PROXY http://127.0.0.1:8080";
    // All other traffic bypass proxy
    return "DIRECT";
}
```

**Application Restrictions**

* **Using Applocker - for Server 2008 R2, Windows 7, or higher:**
  * Rules for executable files (.exe, .com)
  * DLL rules (.dll, .ocx)
  * Script rules (.ps1, .bat, .cmd, .vbs, .js)
  * Installation program rules (.msi, .msp, .mst)

**Working Steps with Applocker (Requires GUI):**

**Step 1:** Create a new GPO.

**Step 2:** Right-click on it to edit, then navigate through `Computer Configuration > Policies > Windows Settings > Security Settings > Application Control Policies > Applocker`. Click "Configure Rule Enforcement".

**Step 3:** Under "Executable Rules", check the "Configured" box and ensure "Enforce Rules" is selected from the drop-down box. Click "OK".

**Step 4:** In the left pane, click "Executable Rules".

**Step 5:** Right-click in the right pane and select "Create New Rule".

**Step 6:** On the "Before You Begin" screen, click "Next".

**Step 7:** On the "Permissions" screen, click "Next".

**Step 8:** On the "Conditions" screen, select the "Publisher" condition and click "Next".

**Step 9:** Click the "Browse" button and navigate to any executable file on your system. It doesn’t matter which one.

**Step 10:** Drag the slider up to "Any Publisher" and then click "Next".

**Step 11:** Click "Next" on the "Exceptions" screen.

**Step 12:** Name the policy, for example, "only run executables that are signed" and click "Create".

**Step 13:** If this is your first time creating an Applocker policy, Windows will prompt you to create a default rule, click "Yes".

**Step 14:** Ensure "Application Identity Service" is Running.

```
C:\> net start AppIDSvc
C:\> REG add "HKLM\SYSTEM\CurrentControlSet\services\AppIDSvc" /v Start /t REG_DWORD /d 2 /f
```

**Step 15:** Changes require a reboot.

```
C:\> shutdown.exe /r
C:\> shutdown.exe /r /m \\<IP ADDRESS OR COMPUTER NAME> /f
```

**Using the Applocker Module in PowerShell:**

* **Import the Applocker Module:**

```
PS C:\> import-module Applocker
```

* **Display Information about Files and Executables in the Path C:\Windows\System32:**

```
PS C:\> Get-ApplockerFileInformation -Directory C:\Windows\System32\ -Recurse -FileType Exe, Script
```

* **Create an Applocker Policy for All Executable Files in the Path C:\Windows\System32:**

```
PS C:\> Get-ApplockerFileInformation -Directory C:\Windows\System32\ -Recurse -FileType Exe, Script
```

* **Create an Applocker Policy to Allow All Executable Files in the Path C:\Windows\System32:**

```
PS C:\> Get-Childitem C:\Windows\System32\*,exe | Get-ApplockerFileInformation | New-ApplockerPolicy -RuleType Publisher, Hash -User Everyone -RuleNamePrefix System32
```

* **Change Existing Policies Using the File C:\Policy.xml:**

```
PS C:\> Set-AppLockerPolicy -XMLPolicy C:\Policy.xml
```

* **Use Applocker Policies to Allow Running notepad and calc for Users Who are Members of the 'everyone' Group:**

```
PS C:\> Test-AppLockerPolicy -XMLPolicy C:\Policy.xml -Path C:\Windows\System32\calc.exe, C:\Windows\System32\notepad.exe -User Everyone
```

* **Create a Restriction for the Number of Executions:**

```
PS C:\> Get-ApplockerFileInformation -EventLog -Logname "Microsoft-Windows-Applocker\EXE and DLL" -EventType Audited -Statistics
```

* **Create a Policy for Applocker from Audited Events for exe and dll Files:**

```
PS C:\> Get-ApplockerFileInformation -EventLog -LogPath "Microsoft-Windows-AppLocker/EXE and DLL" -EventType Audited | New-ApplockerPolicy -RuleType Publisher, Hash -User domain\<GROUP> -IgnoreMissingFileInformation | Set-ApplockerPolicy -LDAP "LDAP://<DC>,<DOMAIN>.com/CN={31B2F340-016D-11D2-945F-00C04FB984F9},CN=Policies,CN=System,DC=<DOMAIN>,DC=com"
```

**Extracting All Applocker Policies:**

```
PS C:\> Get-AppLockerPolicy -Local | Test-AppLockerPolicy -Path C:\Windows\System32\*.exe -User domain\<USER NAME> -Filter Denied | Format-List -Property Path > C:\DeniedFiles.txt
```

**Review and Test the Extracted Applocker Policy File:**

```
PS C:\> Get-Childitem <DirectoryPathToReview> -Filter <FileExtensionFilter> -Recurse | Convert-Path | Test-ApplockerPolicy -XMLPolicy <PathToExportedPolicyFile> -User <domain\username> -Filter <TypeOfRuleToFilterFor> | Export-CSV <PathToExportResultsTo.CSV>
```

**Display a GridView List for All Rules:**

```
PS C:\> Get-AppLockerPolicy -Local -Xml | Out-GridView
```

**IPSEC Commands**

**Create a Local Security Policy for Applocker for Any Type of Connection and Protocol Using a Preshared Key:**

```
C:\> netsh ipsec static add filter filterlist=MyIPsecFilter srcaddr=Any dstaddr=Any protocol=ANY
C:\> netsh ipsec static add filteraction name=MyIPsecAction action=negotiate
C:\> netsh ipsec static add policy name=MyIPsecPolicy assign=yes
C:\> netsh ipsec static add rule name=MyIPsecRule policy=MyIPsecPolicy filterlist=MyIPsecFilter filteraction=MyIPsecAction conntype=all activate=yes psk=<PASSWORD>
```

**Add a Rule for Allowing Ports 80 and 443 in IPSEC:**

```
C:\> netsh ipsec static add filteraction name=Allow action=permit
C:\> netsh ipsec static add filter filterlist=WebFilter srcaddr=Any dstaddr=Any protocol=TCP dstport=80
C:\> netsh ipsec static add filter filterlist=WebFilter srcaddr=Any dstaddr=Any protocol=TCP dstport=443
C:\> netsh ipsec static add rule name=WebAllow policy=MyIPsecPolicy filterlist=WebFilter filteraction=Allow conntype=all activate=yes psk=<PASSWORD>
```

**Display All Local Security Policies in IPSEC Named "MyIPsecPolicy":**

```
C:\> netsh ipsec static show policy name=MyIPsecPolicy
```

**Stop or Disable Policies in IPSEC:**

```
C:\> netsh ipsec static set policy name=MyIPsecPolicy
```

**Create a New Policy, Rule, and Preshared Key for Any Type of Connection:**

```
C:\> netsh advfirewall consec add rule name="IPSEC" endpoint1=any endpoint2=any action=requireinrequireout qmsecmethods=default
```

**Require a Preshared Key for All Outgoing Requests in IPSEC:**

```
C:\> netsh advfirewall firewall add rule name="IPSEC_Out" dir=out action=allow enable=yes profile=any localip=any remoteip=any protocol=any interfacetype=any security=authenticate
```

**Create a Rule for Web Browsing:**

```
C:\> netsh advfirewall firewall add rule name="Allow Outbound Port 80" dir=out localport=80 protocol=TCP action=allow
```

**Create a Rule for DNS:**

```
C:\> netsh advfirewall firewall add rule name="Allow Outbound Port 53" dir=out localport=53 protocol=UDP action=allow
```

**Delete Rule in IPSEC:**

```
C:\> netsh advfirewall firewall delete rule name="IPSEC_RULE"
```

**ACTIVE DIRECTORY (AD) and GROUP POLICY OBJECT (GPO)**

**Retrieve and Apply New Policies:**

```
C:\> gpupdate /force
C:\> gpupdate /sync
```

**Audit Success and Failure for User Bob:**

```
C:\> auditpol /set /user:bob /category:"Detailed Tracking" /include /success:enable /failure:enable
```

**Create an Organization Unit to Transfer Suspect Users and Computers:**

```
C:\> dsadd OU <QUARANTINE BAD OU>
```

**Transfer active directory users to a new group "NEW GROUP":**

```
PS C:\> Move-ADObject 'CN=<USER NAME>,CN=<OLD USER GROUP>,DC=<OLD DOMAIN>,DC=<OLD EXTENSION>' -TargetPath 'OU=<NEW USER GROUP>,DC=<OLD DOMAIN>,DC=<OLD EXTENSION>'
```

Similar Method:

```
C:\> dsmove "CN=<USER NAME>,OU=<OLD USER OU>,DC=<OLD DOMAIN>,DC=<OLD EXTENSION>" -newparent OU=<NEW USER GROUP>,DC=<OLD DOMAIN>,DC=<OLD EXTENSION>
```

**System Without ACTIVE DIRECTORY (AD)**

**Prevent .exe file:**

```
C:\> reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v DisallowRun /t REG_DWORD /d "00000001" /f
C:\> reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun" /v badfile.exe /t REG_SZ /d <BAD FILE NAME>.exe /f
```

**Disable Remote Desktop:**

```
C:\> reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /f /v fDenyTSConnections /t REG_DWORD /d 1
```

**Only send NTLMv2 responses to LM & NTLM: (default in Windows 7)**

```
C:\> reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa\ /v lmcompatibilitylevel /t REG_DWORD /d 5 /f
```

**Limit anonymous access:**

```
C:\> reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v restrictanonymous /t REG_DWORD /d 1 /f
```

**Do not allow anonymous access to SAM accounts and shares:**

```
C:\> reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v restrictanonymoussam /t REG_DWORD /d 1 /f
```

**Disable IPV6:**

```
C:\> reg add HKLM\SYSTEM\CurrentControlSet\services\TCPIP6\Parameters /v DisabledComponents /t REG_DWORD /d 255 /f
```

**Disable sticky keys:**

```
C:\> reg add "HKCU\Control Panel\Accessibility\StickyKeys" /v Flags /t REG_SZ /d 506 /f
```

**Disable toggle keys:**

```
C:\> reg add "HKCU\Control Panel\Accessibility\ToggleKeys" /v Flags /t REG_SZ /d 58 /f
```

**Disable filter keys:**

```
C:\> reg add "HKCU\Control Panel\Accessibility\Keyboard Response" /v Flags /t REG_SZ /d 122 /f
```

**Disable On-screen Keyboard:**

```
C:\> reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI /f /v ShowTabletKeyboard /t REG_DWORD /d 0
```

**Disable Administrative Shares - Workstations:**

```
C:\> reg add HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters /f /v AutoShareWks /t REG_DWORD /d 0
```

**Disable Administrative Shares - Servers:**

```
C:\> reg add HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters /f /v AutoShareServer /t REG_DWORD /d 0
```

**Delete hashes related to the Pass the Hash attack (requires reboot and password change for old hashes):**

```
C:\> reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /f /v NoLMHash /t REG_DWORD /d 1
```

**Disable Registry Editing: (High Risk)**

```
C:\> reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System /v DisableRegistryTools /t REG_DWORD /d 1 /f
```

**Disable IE Password Cache:**

```
C:\> reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings /v DisablePasswordCaching /t REG_DWORD /d 1 /f
```

**Disable CMD prompt:**

```
C:\> reg add HKCU\Software\Policies\Microsoft\Windows\System /v DisableCMD /t REG_DWORD /d 1 /f
```

**Disable caching of admin credentials in the host using rdp:**

```
C:\> reg add HKLM\System\CurrentControlSet\Control\Lsa /v DisableRestrictedAdmin /t REG_DWORD /d 0 /f
```

**Do not process files that have only been run once:**

```
C:\> reg add HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer /v DisableLocalMachineRunOnce /t REG_DWORD /d 1
C:\> reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer /v DisableLocalMachineRunOnce /t REG_DWORD /d 1
```

**Require User Access Control (UAC):**

```
C:\> reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA /t REG_DWORD /d 1 /f
```

**Change the password after logging in again:**

```
PS C:\> Set-ADAccountPassword <USER> -NewPassword $newpwd -Reset -PassThru | Set-ADuser -ChangePasswordAtLogon $True
```

**PowerShell Script for Windows**

**Change the password on the next login for the OU Group:**

```
PS C:\> Get-ADuser -filter "department -eq '<OU GROUP>' -AND enabled -eq 'True'" | Set-ADuser -ChangePasswordAtLogon $True
```

**Enable logging in the firewall:**

```
PS C:\> netsh firewall set logging droppedpackets=enable connections=enable
```

**Bash Script for Linux**

**Service Information, List, Start, and Stop services in Ubuntu, and List All Services:**

```
Service Information:
service --status-all
ps -ef
ps -aux
# List, Start, and Stop services in Ubuntu:
/etc/init.d/apache2 start
/etc/init.d/apache2 restart
/etc/init.d/apache2 stop # (stops only until reboot)
service mysql start
service mysql restart
service mysql stop # (stops only until reboot)
# List All Boot Up services:
ls /etc/init/*.conf
# Check Boot Up service status:
status ssh
```

**Example Firewall (iptables) Commands:**

```
Save All Existing iptables Rules:
iptables-save > firewall.out
# Edit File Containing Rules:
vi firewall.out
# Reload iptables Rules:
iptables-restore < firewall.out
# Example iptables Commands to Limit IPs and Ports:
iptables -A INPUT -s 10.10.10.10 -j DROP
iptables -A INPUT -s 10.10.10.0/24 -j DROP
iptables -A INPUT -p tcp --dport ssh -s 10.10.10.10 -j DROP
iptables -A INPUT -p tcp --dport ssh -j DROP
# Block All Connections:
iptables -P INPUT DROP
iptables -P OUTPUT DROP
iptables -P FORWARD DROP
# Logging All Denied Rules in iptables:
iptables -I INPUT 5 -m limit --limit 5/min -j LOG --log-prefix "iptables denied: " --log-level 7
```

**Example Password Commands:**

```
Change Password:
passwd # (For current user)
passwd bob # (For user Bob)
sudo su passwd # (For root)
```

**Example Host File Commands:**

```
Add Malicious Domain and Redirect to localhost:
echo "127.0.0.1 <MALICIOUS DOMAIN>" >> /etc/hosts
# Check Host Files by Pinging 127.0.0.1:
ping -c 1 <MALICIOUS DOMAIN>
# Restart DNS cache in Ubuntu:
/etc/init.d/dns-clean start
```

**Example IPSEC Commands:**

```
Allow Firewall for IPSEC Traffic:
iptables -A INPUT -p esp -j ACCEPT
iptables -A INPUT -p ah -j ACCEPT
iptables -A INPUT -p udp --dport 500 -j ACCEPT
iptables -A INPUT -p udp --dport 4500 -j ACCEPT
# IPSEC Traffic Pass Setup using Racoon:
# Step 1: Install Racoon on <HOST1 IP ADDRESS> and <HOST2 IP ADDRESS> to enable IPSEC tunneling in Ubuntu.
apt-get install racoon
# Steps 2, 3, 4, and 5 need further manual configurations as per original text.
```
