# Identify Scope

**Identification (Domain)**

* Scan and Vulnerabilities

**NMAP Command**

* Using Ping sweep for the network:

```
shellCopy code# nmap -sn -PE <IP ADDRESS OR RANGE>
```

* Scan and display open ports:

```
shellCopy code# nmap --open <IP ADDRESS OR RANGE>
```

* Determine open services:

```
shellCopy code# nmap -sV <IP ADDRESS>
```

* Scan http and https (tcp) ports:

```
shellCopy code# nmap -p 80,443 <IP ADDRESS OR RANGE>
```

* Scan DNS (udp):

```
shellCopy code# nmap -sU -p 53 <IP ADDRESS OR RANGE>
```

* Scan UDP and TCP together, be verbose on a single host and include optional skip ping:

```
shellCopy code# nmap -v -Pn -SU -ST -p U:53,111,137,T:21-25,80,139,8080 <IP ADDRESS>
```

**NESSUS Command**

* Basic Nessus Scan:

```
shellCopy code# nessus -q -x -T html <NESSUS SERVER IP ADDRESS> <NESSUS SERVER PORT 1241> <ADMIN ACCOUNT> <ADMIN PASSWORD> <FILE WITH TARGETS>.txt <RESULTS FILE NAME>.html
# nessus [-vnh] [-c .refile] [-VJ [-T <format>]
```

* Batch-mode Scan:

```
shellCopy code# nessus -q [-pPS] <HOST> <PORT> <USERNAME> <PASSWORD> <targets-file> <result-file>
```

* Get the report:

```
shellCopy code# nessus -i in.[nsrlnbe] -o out.[xmllnsrlnbelhtmlltxt]
```

**OPENVAS Command**

* Step 1: Install server, client, and plugins:

```
shellCopy code# apt-get install openvas-server openvas-client openvas-plugins-base openvas-plugins-dfsg
```

* Step 2: Update the vulnerability database:

```
shellCopy code# openvas-nvt-sync
```

* Step 3: Add a user to the client:

```
shellCopy code# openvas-adduser
```

* Step 4: Log in: sysadm
* Step 5: Authenticate (pass/cert) \[pass]: \[HIT ENTER]
* Step 6: Enter password: Based on the added user policies
*   Step 7: Allow the user to scan networks requiring authentication:

    ```
    shellCopy codeaccept <YOUR IP ADDRESS OR RANGE>
    default deny
    ```
* Step 8: Use Ctrl+D key combination to exit.
* Step 9: Start the server:

```
shellCopy code# service openvas-server start
```

* Step 10: Choose the target for the scan: Create a file containing the targets.

```
shellCopy code# vi scanme.txt
```

* Step 11: Add various hosts on each line:

```
shellCopy code<IP ADDRESS OR RANGE>
```

* Step 12: Begin scan:

```
shellCopy code# openvas-client -q 127.0.0.1 9390 sysadm nsrc+ws scanme.txt openvas-output-.html -T txt -V -x
```

* Step 13: (Optional) Start the scan in HTML format:

```
shellCopy code# openvas-client -q 127.0.0.1 9390 sysadm nsrc+ws scanme.txt openvas-output.txt -T html -V -x
```

**Windows**

* Network Identification
* Basic Network Identification:

```
shellCopy codeC:> net view /all
C:> net view \\<HOST NAME>
```

* Using ping to scan and save the result in a file:

```
shellCopy codeC:\> for /L %I in (1,1,254) do ping -w 30 -n 1 192.168.1.%I | find "Reply" >> <OUTPUT FILE NAME>.txt
```

```
bashCopy codenbtscan <IP ADDRESS OR RANGE>
```

* Basic nbtstat scan:

```
bashCopy code# find /<PATHNAME TO ENUMERATE> -type f -exec md5sum {} >> md5sums.txt \;
```

* Hashing all executable files in a specific path:

```
bashCopy coderndc querylog
# tail -f /var/log/messages | grep named
```

* DNS reporting start and viewing DNS reports:

```
bashCopy code# cat /var/lib/dhcpd/dhcpd.leases
# grep -Ei 'dhcp' /var/log/syslog.1
```

* View DHCP reports on Red Hat 3 and Ubuntu:

```
bashCopy code# smbtree -b
```

* Network Identification:

**Linux**

```
batchCopy codeC:\> dsquery ou DC=<DOMAIN>,DC=<DOMAIN EXTENSION>
```

* Commands to list all OUs, workstations, servers, domain controllers, and more:

**Active Directory Inventory**

```
batchCopy codeC:\> mbsacli.exe /target <TARGET IP ADDRESS> /n os+iis+sql+password
```

* Basic scans for target IP, IP range, domain, and names within a text file:

**Microsoft Baseline Security Analyzer (MBSA)**

```
batchCopy code:: batch script lines to test usernames and passwords against a target IP
```

* Guess or check password:

**Passwords**

```
batchCopy codeC:\> for /L %i in (1,1,254) do psloggedon \\192.168.1.%i >> C:\users\_output.txt
```

* Loop scan script:

```
batchCopy codeC:\> psloggedon \\computername
```

* Display logged-on user:

**User Activities**

```
batchCopy codeC:\> nbtstat -A <IP ADDRESS>
C:\> for /L %I in (1,1,254) do nbtstat -An 192.168.1.%I
```

* Basic nbtstat scan and loop scan script:

**NETBIOS**

```
batchCopy codeC:\> Get-FileHash <FILE TO HASH> | Format-List
C:\> certutil -hashfile <FILE TO HASH> SHA1
```

* And other hash, file verification, and checksum operations with commands such as:

```
batchCopy codeC:\> fciv.exe <FILE TO HASH>
C:\> fciv.exe c:\ -r -md5 -xml <FILE NAME>.xml
```

* Using the File Checksum Integrity Verifier (FCIV) software:

**Hashing**

```
batchCopy codeC:\> DNSCmd <DNS SERVER NAME> /config /LogFilePath <PATH TO LOG FILE>
C:\> DNSCmd <DNS SERVER NAME> /config /logfilemaxsize 0xffffffff
```

* Log path setup, log file size configuration, etc.:

```
batchCopy codeC:\> DNSCmd <DNS SERVER NAME> /config /logLevel 0x8100F331
```

* Enabling DNS Logging:

```
batchCopy codeC:\> %SystemRoot%\System32\Dns 
C:\> %SystemRoot%\System32\Winevt\Logs\DNS Server.evtx
C:\> %SystemRoot%\System32\Winevt\Logs\Microsoft-Windows-DNSServer%4Analytical.etl
```

* Default paths for various Windows versions:

**DNS**

```
batchCopy codeC:> %windir%\System32\Dhcp
```

* Default paths for various Windows versions:

```
batchCopy codeC:\> reg add HKLM\System\CurrentControlSet\Services\DhcpServer\Parameters /v ActivityLogFlag /t REG_DWORD /d 1
```

* Enabling DHCP Reports:

**DHCP**

* Enabling DHCP Reports:

```
batchCopy codeC:\> reg add HKLM\System\CurrentControlSet\Services\DhcpServer\Parameters /v ActivityLogFlag /t REG_DWORD /d 1
```

* Default paths for various Windows versions:

```
batchCopy codeC:> %windir%\System32\Dhcp
```

**DNS**

* Default paths for various Windows versions:

```
batchCopy codeC:\> %SystemRoot%\System32\Dns 
C:\> %SystemRoot%\System32\Winevt\Logs\DNS Server.evtx
C:\> %SystemRoot%\System32\Winevt\Logs\Microsoft-Windows-DNSServer%4Analytical.etl
```

* Enabling DNS Logging:

```
batchCopy codeC:\> DNSCmd <DNS SERVER NAME> /config /logLevel 0x8100F331
```

* Log path setup, log file size configuration, etc.:

```
batchCopy codeC:\> DNSCmd <DNS SERVER NAME> /config /LogFilePath <PATH TO LOG FILE>
C:\> DNSCmd <DNS SERVER NAME> /config /logfilemaxsize 0xffffffff
```

**Hashing**

* Using the File Checksum Integrity Verifier (FCIV) software:

```
batchCopy codeC:\> fciv.exe <FILE TO HASH>
C:\> fciv.exe c:\ -r -md5 -xml <FILE NAME>.xml
```

* And other hash, file verification, and checksum operations with commands such as:

```
batchCopy codeC:\> Get-FileHash <FILE TO HASH> | Format-List
C:\> certutil -hashfile <FILE TO HASH> SHA1
```

**NETBIOS**

* Basic nbtstat scan and loop scan script:

```
batchCopy codeC:\> nbtstat -A <IP ADDRESS>
C:\> for /L %I in (1,1,254) do nbtstat -An 192.168.1.%I
```

**User Activities**

* Display logged-on user:

```
batchCopy codeC:\> psloggedon \\computername
```

* Loop scan script:

```
batchCopy codeC:\> for /L %i in (1,1,254) do psloggedon \\192.168.1.%i >> C:\users\_output.txt
```

**Passwords**

* Guess or check password:

```
batchCopy code:: batch script lines to test usernames and passwords against a target IP
```

**Microsoft Baseline Security Analyzer (MBSA)**

* Basic scans for target IP, IP range, domain, and names within a text file:

```
batchCopy codeC:\> mbsacli.exe /target <TARGET IP ADDRESS> /n os+iis+sql+password
```

**Active Directory Inventory**

* Commands to list all OUs, workstations, servers, domain controllers, and more:

```
batchCopy codeC:\> dsquery ou DC=<DOMAIN>,DC=<DOMAIN EXTENSION>
```

**Linux**

* Network Identification:

```
bashCopy code# smbtree -b
```

* View DHCP reports on Red Hat 3 and Ubuntu:

```
bashCopy code# cat /var/lib/dhcpd/dhcpd.leases
# grep -Ei 'dhcp' /var/log/syslog.1
```

* DNS reporting start and viewing DNS reports:

```
bashCopy coderndc querylog
# tail -f /var/log/messages | grep named
```

* Hashing all executable files in a specific path:

```
bashCopy code# find /<PATHNAME TO ENUMERATE> -type f -exec md5sum {} >> md5sums.txt \;
```

* Basic nbtstat scan:

```
bashCopy codenbtscan <IP ADDRESS OR RANGE>
```

* Guess Passwords:

```
while read line; do username=$line; while read
line; do smbclient -L <TARGET IP ADDRESS> -U
$username%$line -g -d 0; echo $username:$line;
done<<PASSWORDS>.txt;done<<USER NAMES>.txt
```
