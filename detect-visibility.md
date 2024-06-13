# Detect Visibility

**Network Monitoring**

**TCPDUMP command**

**Display traffic in ASCII (-A) or HEX (-X):**

```
# tcpdump -A
# tcpdump -X
```

**Display traffic timestamps and avoid address conversion and be verbose:**

**Identify senders after receiving 1000 packets (possible DDoS attack):**

```
# tcpdump -nn -c 1000 | awk '{print $3}' | cut -d. -f1-4 | sort -n | uniq -c | sort -nr
```

**Capture all exchanged packets on all host interfaces and port 80, and save them to a file:**

```
# tcpdump -w <FILENAME>.pcap -i any dst <TARGET_IP_ADDRESS> and port 80
```

**Display traffic between two hosts:**

```
# tcpdump host 10.0.0.1 and host 10.0.0.2
```

**Display all traffic except for a specified network and host range:**

```
# tcpdump not net 10.10.0.0/16 and not host 192.168.1.2
```

**Display traffic between Host 1 and other hosts:**

```
# tcpdump host 10.10.10.10 and \(host 10.10.10.20 or host 10.10.10.30\)
```

**Save a pcap file with a specified size:**

```
# tcpdump -n -s65535 -C 1000 -w '%host_%Y-%m-%d_%H:%M:%S.pcap'
```

**Save a pcap file on another system:**

```
# tcpdump -w - | ssh <REMOTE_HOST_ADDRESS> -p 50005 "cat - > /tmp/remotecapture.pcap"
```

**Examine and search traffic for the word 'pass':**

```
# tcpdump -n -A -s0 | grep pass
```

**Examine and search traffic for clear text protocols:**

```
# tcpdump -n -A -s0 port http or port ftp or port smtp or port imap or port pop3 | egrep -i 'pass=|pwd=|log=|login=|user=|username=|pw=|passw=|passwd=|password=|pass:|user:|username:|password:|login:|pass|user' --color=auto --line-buffered -B20
```

**Check power or throughput:**

```
# tcpdump -w - | pv -bert >/dev/null
```

**Filter ipv6 traffic:**

**Filter ipv4 traffic:**

**Script to save traffic from multiple interfaces to a file in a timely manner:**

```
#!/bin/bash
tcpdump -pni any -s65535 -G 3600 -w 'any%Y-%m-%d_%H:%M:%S.pcap'
```

**Script for transferring tcpdump traffic files to other locations:**

```
#!/bin/bash
while true; do
  sleep 1;
  rsync -azvr --progress <USER_NAME>@<IP_ADDRESS>:<TRAFFIC_DIRECTORY>/ <DESTINATION_DIRECTORY>/
done
```

**Search for self-signed and suspicious certificates:**

```
# tcpdump -s 1500 -A '(tcp[((tcp[12:1] & 0xf0) >> 2)+5:1] = 0x01) and (tcp[((tcp[12:1] & 0xf0) >> 2):1] = 0x16)'
```

**Display SSL Certificates:**

```
# openssl s_client -connect <URL>:443
# openssl s_client -connect <SITE>:443 </dev/null 2>/dev/null | sed -ne '/-BEGIN CERTIFICATE-/,/-END CERTIFICATE-/p' > <CERT>.pem
```

**Check Self-Signed Certificates:**

```
# openssl x509 -text -in <CERT>.pem
# openssl x509 -in <CERT>.pem -noout -issuer -subject -startdate -enddate -fingerprint
# openssl verify <CERT>.pem
```

**Extract server name in certificates:**

```
# tshark -nr <PCAP FILE NAME> -Y "ssl.handshake.ciphersuites" -Vx | grep "Server Name:" | sort | uniq -c | sort -r
```

**Extract information about certificates:**

```
# ssldump -Nr <FILE NAME>.pcap | awk 'BEGIN {c=0;} { if ($0 ~ /Certificate$/) {c=1; print "========================================";} if ($0 !~/[[:space:]]+/) {c=0;} if (c==1) print $0; }'
```

**Check the status of applications and each port usage:**

```
netstat -aon | findstr '[port_number]'
tasklist | findstr '[PID]'
tasklist | findstr '[application_name]'
netstat -aon | findstr '[PID]'
```

**TSHARK Command** Get network interfaces:

Check several network interfaces:

```
tshark -i eth1 -i eth2 -i eth3
```

Save pcap and disable name resolution:

```
tshark -nn -w <FILE NAME>.pcap
```

... and more commands follow in similar fashion.

**Extract POST request values**

```
tshark -Y "http.request.method==POST" -T fields -e http.file_data -r keeptryin.pcap
```

**Extract DNS response values**

```
codetshark -Y "dns.txt" -T fields -e dns.qry.name -n -r keeptryin.pcap
```

**SNORT Command** Run a test on the snort settings file:

```
# snort -T -c /<PATH TO SNORT>/snort/snort.conf
```

**Tools to inspect network traffic or PCAP files**

**EDITCAP tool** Edit pcap files (separate 1000 packets):

```
editcap -F pcap -c 1000 original.pcap out_split.pcap
```

Edit pcap files (separate packets per hour):

```
editcap -F pcap -t+3600 original.pcap out_split.pcap
```

**MERGECAP tool** To merge several pcap files:

```
mergecap -w merged_cap.pcap cap1.pcap cap2.pcap cap3.pcap
```

**Technique: HONEY**

**Windows**

**Honey Ports on Windows:**

_Source:_ [_http://securityweekly.com/wp-content/uploads/2013/06/howtogetabetterpentest.pdf_](http://securityweekly.com/wp-content/uploads/2013/06/howtogetabetterpentest.pdf)

**Step 1:** Create a firewall rule to identify and deny all connections to port 3333.

```
echo @echo off for /L %%i in (1,1,1) do @for /f "tokens=3" %%j in ('netstat -nao | find "":3333 "') do @for /f "tokens=1 delims=:" %%k in ("%%j") do netsh advfirewall firewall add rule name="HONEY TOKEN RULE" dir=in remoteip=%%k localport=any protocol=TCP action=block >> <BATCH_FILE_NAME>.bat
```

**Step 2:** Execute the batch script.

_... (additional steps for honey hashes and detection methods with PowerShell and batch script)..._

**Linux**

**Honey Ports on Linux:**

_Source:_ [_http://securityweekly.com/wp-content/uploads/2013/06/howtogetabetterpentest.pdf_](http://securityweekly.com/wp-content/uploads/2013/06/howtogetabetterpentest.pdf)

**Step 1:** Create a loop to reject all requests to port 2222.

```
while [ 1 ]; do IP=$(nc -v -l -p 2222 2>&1 | grep from | cut -d[ -f 3 | cut -d] -f 1); iptables -A INPUT -p tcp -s ${IP} -j DROP; done
```

**Honey Port Script on Linux:**

_Source:_ [_https://github.com/gchetrick/honeyports/blob/master/honeyports-0.5.py_](https://github.com/gchetrick/honeyports/blob/master/honeyports-0.5.py)

**Step 1:** Download the Python script.

```
wget https://github.com/gchetrick/honeyports/blob/master/honeyports-0.5.py
```

**Step 2:** Execute the Python script.

```
python honeyports-0.5.py -p <CHOOSE_AN_OPEN_PORT> -h <HOST_IP_ADDRESS>
```

_... (additional steps for using netcat, passive DNS monitoring, and log auditing)..._

**LOG AUDITING METHODS**

**Windows**

**Increase Log Size for Better Auditing:**

```
reg add HKLM\Software\Policies\Microsoft\Windows\EventLog\Application /v MaxSize /t REG_DWORD /d 0x19000
reg add HKLM\Software\Policies\Microsoft\Windows\EventLog\Security /v MaxSize /t REG_DWORD /d 0x64000
reg add HKLM\Software\Policies\Microsoft\Windows\EventLog\System /v MaxSize /t REG_DWORD /d 0x19000
```

**Check Security Log Settings:**

**For Audit Policy Settings:**

```
auditpol /get /category:*
```

**Set Log Auditing (successful or unsuccessful) in All Categories:**

```
C: \> auditpol /set /subcategory: "Detailed File
Share" /success:enable /failure:enable
C:\> auditpol /set /subcategory:"File System"
/success:enable /failure:enable
C:\> auditpol /set /subcategory:"Security System
Extension" /success:enable /failure:enable
C:\> auditpol /set /subcategory:"System Integrity"
/success:enable /failure:enable
C:\> auditpol /set /subcategory:"Security State
Change" /success:enable /failure:enable
C:\> auditpol /set /subcategory:"Other System
Events" /success:enable /failure:enable
C:\> auditpol /set /subcategory:"System Integrity"
/success:enable /failure:enable
C:\> auditpol /set /subcategory:"Logon"
/success:enable /failure:enable
C:\> auditpol /set /subcategory:"Logoff"
/success:enable /failure:enable
C:\> auditpol /set /subcategory:"Account Lockout"
/success:enable /failure:enable
C:\> auditpol /set /subcategory:"Other Logon/Logoff
Events" /success:enable /failure:enable
C:\> auditpol /set /subcategory:"Network Policy
Server" /success:enable /failure:enable
C:\> auditpol /set /subcategory:"Registry"
/success:enable /failure:enable
C:\> auditpol /set /subcategory:"SAM"
/success:enable /failure:enable
C:\> auditpol /set /subcategory:"Certification
Services" /success:enable /failure:enable
C:\> auditpol /set /subcategory:"Application
Generated" /success:enable /failure:enable
C: \> auditpol / set /subcategory: "Handle
Manipulation" /success:enable /failure:enable
C:\> auditpol /set /subcategory:"file Share"
/success:enable /failure:enable
C:\> auditpol /set /subcategory:"filtering Platform
Packet Drop" /success:enable /failure:enable
C:\> auditpol /set /subcategory:"Filtering Platform
Connection" /success:enable /failure:enable
C:\> auditpol /set /subcategory:"Other Object Access
Events" /success:enable /failure:enable
C: \> auditpol /set /subcategory: "Detailed File
Share" /success:enable /failure:enable
C: \> auditpol /set /subcategory: "Sensitive Privilege
Use" /success:enable /failure:enable
C: \> auditpol /set /subcategory: "Non Sensitive
Privilege Use" /success:enable /failure:enable
C: \> auditpol /set /subcategory: "Other Privilege Use
Events" /success:enable /failure:enable
C:\> auditpol /set /subcategory:"Process
Termination" /success:enable /failure:enable
C:\> auditpol /set /subcategory: "DPAPI Activity"
/success:enable /failure:enable
C: \> audit pol /set /subcategory: "RPC Events"
/success:enable /failure:enable
C:\> auditpol /set /subcategory:"Process Creation"
/success:enable /failure:enable
C:\> auditpol /set /subcategory:"Audit Policy
Change" /success:enable /failure:enable
C:\> auditpol /set /subcategory: "Authentication
Policy Change" /success:enable /failure:enable
C:\> auditpol /set /subcategory: "Authorization
Policy Change" /success:enable /failure:enable
C: \> audit pol /set /subcategory: "MPSSVC Rule-Level
Policy Change" /success:enable /failure:enable
C:\> auditpol /set /subcategory:"Filtering Platform
Policy Change" /success:enable /failure:enable
C:\> auditpol /set /subcategory:"Other Policy Change
Events" /success:enable /failure:enable
C:\> auditpol /set /subcategory:"User Account
Management" /success:enable /failure:enable
C:\> auditpol /set /subcategory:"Computer Account
Management" /success:enable /failure:enable
C:\> auditpol /set /subcategory:"Security Group
Management" /success:enable /failure:enable
C:\> auditpol /set /subcategory:"Distribution Group
Management" /success:enable /failure:enable
C:\> auditpol /set /subcategory:"Application Group
Management" /success:enable /failure:enable
C:\> auditpol /set /subcategory:"Other Account
Management Events" /success:enable /failure:enable
C:\> auditpol /set /subcategory:"Directory Service
Changes" /success:enable /failure:enable
C: \> auditpol / set /subcategory: "Directory Service
Replication" /success:enable /failure:enable
C:\> auditpol /set /subcategory:"Detailed Directory
Service Replication" /success:enable /failure:enable
C:\> auditpol /set /subcategory:"Directory Service
Access" /success:enable /failure:enable
C:\> auditpol /set /subcategory:"Kerberos Service
Ticket Operations" /success:enable /failure:enable
C:\> auditpol /set /subcategory:"Other Account Logan
Events" /success:enable /failure:enable
C: \> audit pol /set /subcategory: "Kerberos
Authentication Service" /success:enable
/failure:enable
C:\> auditpol /set /subcategory:"Credential
Validation" /success:enable /failure:enable
```

**Available Reports List and Sizes and Allowed:**

Available reports list and their sizes and permitted:

```
PS C:\> Get-Eventlog -list
```

**Partial List of Security Log Auditing Events Keys:**

Partial list of keys for monitoring Security Log Auditing events:

```
PS C:\> Get-Eventlog -newest 5 -logname application | Format-List
```

**Display Reports Remotely:**

Displaying reports remotely:

```
PS C:\> Show-Eventlog -computername <SERVER NAME>
```

**Display Event List Based on Event ID:**

Displaying the list of events based on Event ID:

```
PS C:\> Get-Eventlog Security | Where-Object { $_.Eventid -eq 4800}
PS C:\> Get-WinEvent -FilterHashtable @{LogName="Security"; ID=4774}
```

**Account Access - Audit Credential Validation for the Last 14 Days:**

Logging in - Audit Credential Validation for the last 14 days:

```
PS C:\> Get-Eventlog Security -InstanceId 4768,4771,4772,4769,4770,4649,4778,4779,4800,4801,4802,4803,5378,5632,5633 -after ((get-date).addDays(-14))
```

**Account - Login and Logout:**

Account - Logins and logouts:

```
PS C:\> Get-Eventlog Security -InstanceId 4625,4634,4647,4624,4625,4648,4675,6272,6273,6274,6275,6276,6277,6278,6279,6280,4649,4778,4779,4800,4801,4802,4803,5378,5632,5633,4964 -after ((get-date).addDays(-1))
```

**Account Management - Audit Group Management Programs:**

Account management - Managing the group of Audit apps:

```
PS C:\> Get-Eventlog Security -InstanceId 4783,4784,4785,4786,4787,4788,4789,4790,4741,4742,4743,4744,4745,4746,4747,4748,4749,4750,4751,4752,4753,4759,4760,4761,4762,4782,4793,4727,4728,4729,4730,4731,4732,4733,4734,4735,4737,4754,4755,4756,4757,4758,4764,4720,4722,4723,4724,4725,4726,4738,4740,4765,4766,4767,4780,4781,4794,5376,5377 -after ((get-date).addDays(-1))
```

**Display Available Event Logs and their Sizes and Quota:**

```
PS C:\> Get-Eventlog -list
```

**Partial List of Security Log Auditing Events Key Monitoring:**

```
PS C:\> Get-Eventlog -newest 5 -logname application | Format-List
```

**Display Logs Remotely:**

```
PS C:\> Show-Eventlog -computername <SERVER NAME>
```

**Display Event List Based on Event ID:**

```
PS C:\> Get-Eventlog Security | Where-Object { $_.Eventid -eq 4800}
PS C:\> Get-WinEvent -FilterHashtable @{LogName="Security"; ID=4774}
```

**Account Login - Audit Credential Validation for the Last 14 Days:**

```
PS C:\> Get-Eventlog Security -InstanceId 4768,4771,4772,4769,4770,4649,4778,4779,4800,4801,4802,4803,5378,5632,5633 -after ((get-date).addDays(-14))
```

**Account - Login and Logout:**

```
PS C:\> Get-Eventlog Security -InstanceId 4625,4634,4647,4624,4625,4648,4675,6272,6273,6274,6275,6276,6277,6278,6279,6280,4649,4778,4779,4800,4801,4802,4803,5378,5632,5633,4964 -after ((get-date).addDays(-1))
```

**Account Management - Audit Group Management Program:**

```
PS C:\> Get-Eventlog Security -InstanceId 4783,4784,4785,4786,4787,4788,4789,4790,4741,4742,4743,4744,4745,4746,4747,4748,4749,4750,4751,4752,4753,4759,4760,4761,4762,4782,4793,4727,4728,4729,4730,4731,4732,4733,4734,4735,4737,4754,4755,4756,4757,4758,4764,4720,4722,4723,4724,4725,4726,4738,4740,4765,4766,4767,4780,4781,4794,5376,5377 -after ((get-date).addDays(-1))
```

**Fine Tracking - Audit DPAPI Activity, Process Termination, RPC Events:**

```
PS C:\> Get-EventLog Security -InstanceId 4692,4693,4694,4695,4689,5712 -after ((get-date).addDays(-1))
```

**Domain Service Access - Audit Access to Directory Service:**

```
PS C:\> Get-EventLog Security -InstanceId 4662,5136,5137,5138,5139,5141 -after ((get-date).addDays(-1))
```

**Object Access - Audit File Share, File System, SAM, Registry, Certificates:**

```
PS C:\> Get-EventLog Security -InstanceId 4671,4691,4698,4699,4700,4701,4702,5148,5149,5888,5889,5890,4657,5039,4659,4660,4661,4663,4656,4658,4690,4874,4875,4880,4881,4882,4884,4885,4888,4890,4891,4892,4895,4896,4898,5145,5140,5142,5143,5144,5168,5140,5142,5143,5144,5168,5140,5142,5143,5144,5168,4664,4985,5152,5153,5031,5140,5150,5151,5154,5155,5156,5157,5158,5159 -after ((get-date).addDays(-1))
```

**Policy Change - Audit Policy Change, Microsoft Protection Service, Windows Filtering Platform:**

```
PS C:\> Get-EventLog Security -InstanceId 4715,4719,4817,4902,4904,4905,4906,4907,4908,4912,4713,4716,4717,4718,4739,4864,4865,4866,4867,4704,4705,4706,4707,4714,4944,4945,4946,4947,4948,4949,4950,4951,4952,4953,4954,4956,4957,4958,5046,5047,5048,5449,5450,4670 -after ((get-date).addDays(-1))
```

**Privilege Use - Audit Sensitive and Non-sensitive Service Privilege Use:**

```
PS C:\> Get-EventLog Security -InstanceId 4672,4673,4674 -after ((get-date).addDays(-1))
```

**System - Audit Security State Change, Security System Extension, System Integrity, System Events:**

```
PS C:\> Get-Eventlog Security -InstanceId 5024,5025,5027,5028,5029,5030,5032,5033,5034,5035,5037,5058,5059,6400,6401,6402,6403,6404,6405,6406,6407,4608,4609,4616,4621,4610,4611,4614,4622,4697,4612,4615,4618,4816,5038,5056,5057,5060,5061,5062,6281 -after ((get-date).addDays(-1))
```

**Add Microsoft IIS Module:**

```
PS C:\> add-pssnapin WebAdministration
PS C:\> Import-Module WebAdministration
```

**Get Information about IIS:**

**Get IIS Path Information:**

```
PS C:\> (Get-WebConfigurationProperty '/system.applicationHost/sites/siteDefaults' -Name 'logfile.directory').Value
```

**List All Installed Software:**

```
PS C:\> Get-WmiObject -Query "SELECT * FROM Win32_Product" | Select-Object Name
```

**List Installed Software on Remote Computer:**

```
PS C:\> Get-WmiObject -Query "SELECT * FROM Win32_Product" -ComputerName <RemoteComputerName> | Select-Object Name
```

**Delete/Uninstall Software:**

```
PS C:\> Get-WmiObject -Query "SELECT * FROM Win32_Product WHERE Name = '<SoftwareName>'" | ForEach-Object { $_.Uninstall() }
```

**Query Users Connected to a Domain Controller:**

```
PS C:\> Get-WmiObject -Class Win32_ComputerSystem -Property UserName
```

**Find Locked Out Accounts:**

```
PS C:\> Search-ADAccount -LockedOut | Select-Object UserPrincipalName
```

* Note: Ensure you have the Active Directory module loaded (`Import-Module ActiveDirectory`) before executing.

**Unlock User Account:**

```
PS C:\> Unlock-ADAccount -Identity <UserName>
```

**Check Service Status:**

```
PS C:\> Get-Service -Name <ServiceName> | Select-Object Status, Name, DisplayName
```

**Start a Service:**

```
PS C:\> Start-Service -Name <ServiceName>
```

**Stop a Service:**

```
PS C:\> Stop-Service -Name <ServiceName>
```

**Check Disk Space:**

```
PS C:\> Get-WmiObject Win32_LogicalDisk | Select-Object DeviceID, @{Name="Size(GB)";Expression={$_.Size/1GB -as [int]}}, @{Name="FreeSpace(GB)";Expression={$_.FreeSpace/1GB -as [int]}}
```

**List All Running Processes:**

```
PS C:\> Get-Process | Select-Object ProcessName, Id
```

**Kill a Process:**

```
PS C:\> Stop-Process -Id <ProcessId>
- or -
PS C:\> Stop-Process -Name <ProcessName>
```

**Get All Available Network Adapters:**

```
PS C:\> Get-NetAdapter | Select-Object Name, Status, MacAddress
```

**Enable Network Adapter:**

```
PS C:\> Enable-NetAdapter -Name <AdapterName>
```

**Disable Network Adapter:**

```
PS C:\> Disable-NetAdapter -Name <AdapterName> -Confirm:$false
```

**Get IP Configuration:**

```
PS C:\> Get-NetIPConfiguration | Select-Object InterfaceAlias, IPv4Address
```

**Set Static IP Address:**

```
PS C:\> New-NetIPAddress -InterfaceAlias <AdapterName> -IPAddress <IPAddress> -PrefixLength <SubnetPrefixLength> -DefaultGateway <DefaultGateway>
```

**Set DNS Servers:**

```
PS C:\> Set-DnsClientServerAddress -InterfaceAlias <AdapterName> -ServerAddresses <DNSServer1>,<DNSServer2>
```

**Create a New Folder:**

```
PS C:\> New-Item -Path <Path> -Name <FolderName> -ItemType Directory
```

**Copy a Folder/File:**

```
PS C:\> Copy-Item -Path <SourcePath> -Destination <DestinationPath>
```

**Move a Folder/File:**

```
PS C:\> Move-Item -Path <SourcePath> -Destination <DestinationPath>
```

**Delete a Folder/File:**

```
PS C:\> Remove-Item -Path <Path> -Recurse -Force
```

**Extract a Zip File:**

```
PS C:\> Expand-Archive -Path <PathToZip> -DestinationPath <ExtractPath>
```

**Compress Files into a Zip:**

```
PS C:\> Compress-Archive -Path <PathToFiles> -DestinationPath <PathToZip>
```

**Get System Uptime:**

```
PS C:\> (Get-Date) - (Get-CimInstance Win32_OperatingSystem).LastBootUpTime
```

**Check Memory Usage:**

```
PS C:\> Get-WmiObject Win32_OperatingSystem | Select-Object @{Name="FreeMemory(GB)";Expression={"{0:N2}" -f ($_.FreePhysicalMemory/1MB)}},@{Name="TotalMemory(GB)";Expression={"{0:N2}" -f ($_.TotalVisibleMemorySize/1MB)}}
```

**View Event Logs:**

```
PS C:\> Get-EventLog -LogName <LogName> -Newest <NumberOfEvents>
```

**Send an Email:**

```
PS C:\> Send-MailMessage -To "<RecipientEmail>" -From "<YourEmail>" -Subject "<Subject>" -Body "<Body>" -SmtpServer <SMTPServer> -Credential (Get-Credential) -UseSsl
```

\*Note: Use `Get-Credential` to provide username and password for the SMTP server.

**Schedule a Task:**

```
PS C:\> $Action = New-ScheduledTaskAction -Execute '<PathToExecutable>'
PS C:\> $Trigger = New-ScheduledTaskTrigger -At <StartTime> -RepetitionInterval <Interval>
PS C:\> Register-ScheduledTask -Action $Action -Trigger $Trigger -User "<Username>" -Password "<Password>" -TaskName "<TaskName>"
```

**Import a CSV File:**

```
PS C:\> $Data = Import-Csv -Path <PathToCsv>
```

**Export Data to a CSV File:**

```
PS C:\> $Data | Export-Csv -Path <PathToCsv> -NoTypeInformation
```

**Get a List of User Profiles:**

```
PS C:\> Get-WmiObject Win32_UserProfile | Select-Object Special, LocalPath
```

**Remove a User Profile:**

```
PS C:\> Get-WmiObject Win32_UserProfile | Where-Object { $_.Special -eq $false and $_.LocalPath -match "<UserName>" } | ForEach-Object { $_.Delete() }
```

**Check Firewall Status:**

```
PS C:\> Get-NetFirewallProfile | Select-Object Name, Enabled
```
