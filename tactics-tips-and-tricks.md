# Tactics Tips And Tricks

**Operating System Cheat Sheet**

**Windows**

* **Using Pipe for outputs and utilizing in clipboard:**

```
C:\> some_command.exe | clip
```

* **Retrieving information from the clipboard and saving it to a file:** (Requires PowerShell 5)

```
PS C:\> Get-Clipboard > clip.txt
```

* **Adding timestamps to log files:**

```
C:\> echo %DATE% %TIME% >> <TXT LOG>.txt
```

* **Remote addition/modification of registry keys:**

```
C:\> reg add \\<REMOTE COMPUTER NAME>\HKLM\Software\<REG KEY INFO>
```

* **Remote retrieval of registry values:**

```
C:\> reg query \\<REMOTE COMPUTER NAME>\HKLM\Software\<REG KEY INFO>
```

* **Checking and testing registry paths:**

```
PS C:\> Test-Path "HKCU:\Software\Microsoft\<HIVE>"
```

* **Remote copy of files:**

```
C:\> robocopy C:\<SOURCE SHARED FOLDER> \\<DESTINATION COMPUTER>\<DESTINATION FOLDER> /E
```

* **Checking various file extensions in a path:**

```
PS C:\> Test-Path C:\Scripts\Archive\* -include *.PS1, *.VBS
```

* **Displaying file contents:**
* **Merging contents of several files:**

```
C:\> type <FILE NAME 1> <FILE NAME 2> <FILE NAME 3> > <NEW FILE NAME>
```

**Desktops**, allowing creation of multiple display pages in Desktop: Source: [https://technet.microsoft.com/enus/sysinternals/cc817881](https://technet.microsoft.com/enus/sysinternals/cc817881)

Executing live:

```
C:\> "%ProgramFiles%\Internet Explorer\iexplore.exe" "https://live.sysinternals.com/desktops.exe"
```

* **Remote mounting and permitting Read and Read/Write:**

```
C:\> net share MyShare_R=c:\<READ ONLY FOLDER> /GRANT:EVERYONE,READ
C:\> net share MyShare_RW=c:\<READ/WRITE FOLDER> /GRANT:EVERYONE,FULL
```

```
C:\> psexec.exe \\<TARGET IP ADDRESS> -u <USER NAME> -p <PASSWORD> /C C:\<PROGRAM>.exe
C:\> psexec @\<TARGET FILE LIST>.txt -u <ADMIN LEVEL USER NAME> -p <PASSWORD> C:\<PROGRAM>.exe >> C:\<OUTPUT FILE NAME>.txt
```

* **Executing a task and sending its result to a shared environment:**

```
C:\> wmic /node:ComputerName process call create cmd.exe /c netstat -an > \\<REMOTE SHARE>\<OUTPUT FILE NAME>.txt"
```

* **Comparing changes between two files:**

```
PS C:\> Compare-Object (Get-Content <LOG FILE NAME 1>.log) -DifferenceObject (Get-Content <LOG FILE NAME 2>.log)
```

* **Executing a task remotely using PowerShell:**

```
PS C:\> Invoke-Command -ComputerName <COMPUTER NAME> {<PS COMMAND>}
```

* **PowerShell commands guide:**

```
PS C:\> Get-Help <PS COMMAND> -full
```

**Linux**

* **Remote traffic inspection and analysis over ssh:**

```
# ssh root@<REMOTE IP ADDRESS OF HOST TO SNIFF> tcpdump -i any -U -s 0 -w - 'not port 22'
```

* **Create a note or data entry in syslog:**

```
# logger "Something important to note in Log"
# dmesg | grep <COMMENT>
```

* **Create a read-only mounting:**

```
# mount -o ro /dev/<YOUR FOLDER OR DRIVE> /mnt
```

* **Remote Mounting over SSH:**

```
# apt-get install sshfs
# adduser <USER NAME> fuse
Log out and log back in.
mkdir /<WHERE TO MOUNT LOCALLY>
# sshfs <REMOTE USER NAME>@<REMOTE HOST>:/<REMOTE PATH> /<WHERE TO MOUNT LOCALLY>
```

* **Creating an SMB share in Linux:**

```
# useradd -m <NEW USER>
# passwd <NEW USER>
# smbpasswd -a <NEW USER>
# echo [Share] >> /etc/samba/smb.conf
# echo path = /<PATH OF FOLDER TO SHARE> >> /etc/samba/smb.conf
# echo available = yes >> /etc/samba/smb.conf
# echo valid users = <NEW USER> >> /etc/samba/smb.conf
# echo read only = no >> /etc/samba/smb.conf
# echo browsable = yes >> /etc/samba/smb.conf
# echo public = yes >> /etc/samba/smb.conf
# echo writable = yes >> /etc/samba/smb.conf
# service smbd restart
```

**Display Remote System Share:**

```
> smb:\\<IP ADDRESS OF LINUX SMB SHARE>
```

**Copy File Remotely to Another System:**

```
> scp <FILE NAME> <USER NAME>@<DESTINATION IP ADDRESS>:/<REMOTE FOLDER>
```

**Create Mount and SMB Shared Environment Remotely in Another System:**

```
# mount -t smbfs -o username=<USER NAME> //<SERVER NAME OR IP ADDRESS>/<SHARE NAME> /mnt/<MOUNT POINT>/
```

**Monitoring Websites and Files:**

```
# while :; do curl -sSr http://<URL> | head -n 1; sleep 60; done
```

**Alternative Method (Reference):**

```
for i in `curl -s -L cnn.com | egrep --only-matching "http(s?):\/\/[^ \"\(\)\<\>]*" | uniq`; 
do curl -s -I $i 2>/dev/null | head -n 1 | cut -d$' ' -f2; sleep 60; done
```

**Decoding**

**Hex Connection**

**Convert from hex to decimal in Windows:**

```
C:\> set /a 0xff
255
PS C:\> 0xff
255
```

**Other Mathematical Operations in Windows:**

```
C:\> set /a 1+2
3
C:\> set /a 3*(9/4)
6
C:\> set /a (2*5)/2
5
C:\> set /a "32>>3"
4
```

**Decrypt Base64 Text within a File:**

```
C:\> certutil -decode <BASE64 ENCODED FILE NAME> <DECODED FILE NAME>
```

**XOR Decryption, Search for http:** _Source:_ [_https://blog.didierstevens.com/programs/xorsearch/_](https://blog.didierstevens.com/programs/xorsearch/)

```
C:\> xorsearch.exe -i -s <INPUT FILE NAME> http
```

**Convert hex to decimal in Linux:**

```
# echo "0xff" | calc -d
= 255
```

**Convert decimal to hex in Linux:**

```
$ echo "25" | calc -h
= 0xff
```

**Decrypt HTML Strings:**

```
PS C:\> Add-Type -AssemblyName System.Web
PS C:\> [System.Uri]::UnescapeDataString("HTTP%3a%2f%2fHello%20World.com")
HTTP://Hello World.com
```

**SNORT Tool**

**SNORT Rules**

**Snort Rules for Identifying Meterpreter Traffic:** _Source:_ [_https://blog.didierstevens.com/2015/06/16/metasploit-meterpreter-reverse-https-snort-rule/_](https://blog.didierstevens.com/2015/06/16/metasploit-meterpreter-reverse-https-snort-rule/)

```
alert tcp $HOME_NET any-> $EXTERNAL_NET $HTTP_PORTS
(msg:"Metasploit User Agent String";
flow:to_server,established; content:"User-Agentl3al
Mozilla/4,0 (compatible\; MSIE 6.0\; Windows NT
5.1) l0d 0al"; http_header; classtype:trojanactivity;
reference:url,blog,didierstevens.com/2015/03/16/quic
kpost-metasploit-user-agent-strings/; sid:1618000;
rev:1;)
alert tcp $HOME_NET any-> $EXTERNAL_NET $HTTP_PORTS
( msg: "Metasploit User Agent St ring";
flow:to_server,established; content:"User-Agentl3al
Mozilla/4.0 (compatible\; MSIE 6,1\; Windows NT) l0d
0al"; http_header; classtype:trojan-activity;
reference:url,blog,didierstevens.com/2015/03/16/quic
kpost-metasploit-user-agent-strings/; sid:1618001;
rev: 1;)
alert tcp $HOME_NET any-> $EXTERNAL_NET $HTTP_PORTS
(msg: "Metasploit User Agent String";
flow:to_server,established; content:"User-Agentl3al
Mozilla/4,0 (compatible\; MSIE 7,0\; Windows NT
6.0) l0d 0al"; http_header; classtype:trojanactivity;
reference:url,blog.didierstevens.com/2015/03/16/quic
kpost-metasploit-user-agent-strings/; sid:1618002;
rev: 1;)
alert tcp $HOME_NET any-> $EXTERNAL_NET $HTTP_PORTS
(msg:"Metasploit User Agent String";
flow:to_server,established; content:"User-Agentl3al
Mozilla/4,0 (compatible\; MSIE 7,0\; Windows NT
6,0\; Trident/4,0\; SIMBAR={7DB0F6DE-8DE7-4841-9084-
28FA914B0F2E}\; SLCCl\; ,Nl0d 0al"; http_header;
classtype:trojan-activity;
reference:url,blog.didierstevens.com/2015/03/16/quic
kpost-metasploit-user-agent-strings/; sid:1618003;
rev: 1;)
alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS
(msg:"Metasploit User Agent String";
flow:to_server,established; content:"User-Agentl3al
Mozilla/4.0 (compatible\; Metasploit RSPEC)l0d 0al";
http_header; classtype:trojan-activity;
reference:url,blog,didierstevens.com/2015/03/16/quic
kpost-metasploit-user-agent-strings/; sid:1618004;
rev: 1;)
alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS
(msg:"Metasploit User Agent String";
flow:to_server,established; content:"User-Agentl3al
Mozilla/5,0 (Windows\; U\; Windows NT 5,1\; en-US)
AppleWebKit/525,13 (KHTML, like Gecko)
Chrome/4.0.221.6 Safari/525,13l0d 0al"; http_header;
classtype:trojan-activity;
reference:url,blog.didierstevens.com/2015/03/16/quic
kpost-metasploit-user-agent-strings/; sid:1618005;
rev: 1;)
alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS
( msg: "Metasploit User Agent St ring";
flow:to_server,established; content:"User-Agentl3al
Mozilla/5.0 (compatible\; Googlebot/2.1\;
+http://www.google.com/bot.html) l0d 0al";
http_header; classtype:trojan-activity;
reference:url,blog,didierstevens.com/2015/03/16/quic
kpost-metasploit-user-agent-strings/; sid:1618006;
rev: 1;)
alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS
(msg: "Metasploit User Agent St ring";
flow:to_server,established; content:"User-Agentl3al
Mozilla/5,0 (compatible\; MSIE 10,0\; Windows NT
6,1\; Trident/6,0) l0d 0al"; http_header;
classtype:trojan-activity;
reference:url,blog.didierstevens.com/2015/03/16/quic
kpost-metasploit-user-agent-strings/; sid:1618007;
rev: 1;)
```

**Snort Rules for Detect PSEXEC:**

[https://github.com/John-Lin/dockersnort/](https://github.com/John-Lin/dockersnort/)blob/master/snortrules-snapshot- 2972/rules/policy-other.rules

```
alert tcp $HOME_NET any -> $HOME_NET [139,445]
(msg:"POLICY-OTHER use of psexec remote
admin ist rat ion tool"; flow: to_server, established;
content:" IFFISMB1A2I"; depth:5; offset:4;
content:"ISC
.00 I p I 00 Is I 00 I e I 00 Ix I 00 I e I 00 I c I 00 I s I 00 Iv I 00 I c" ;
nocase; metadata:service netbios-ssn;
reference:url,technet.microsoft.com/enus/
sysinternals/bb897553.aspx; classtype:policyviolation;
sid:24008; rev:1;)
alert tcp $HOME_NET any -> $HOME_NET [139,445]
(msg:"POLICY-OTHER use of psexec remote
administration tool SMBv2";
flow:to_server,established; content:"IFEISMB";
depth:8; nocase; content:"105 001"; within:2;
distance:8;
content:"Pl001Sl00IEl00IXl00IEl00ISl00IVl00ICl00I";
fast_pattern:only; metadata:service netbios-ssn;
reference:url,technet.microsoft,com/enus/
sysinternals/bb897553.aspx[l]; classtype:policyviolation;
sid:30281; rev:1;)
```

_Signature of DOS and DDOS Attacks_

**Methods of DoS and DDoS Attacks:** _Source:_ [_https://www.trustwave.com/Resources/SpiderLabs-Blog/PCAP-Files-Are-Great-Aren-t-They–/_](https://www.trustwave.com/Resources/SpiderLabs-Blog/PCAP-Files-Are-Great-Aren-t-They%E2%80%93/)

**Based on Volume:** For example, bandwidth usage reaches from 1 GB to 10 GB. _Source:_ [_http://freecode.com/projects/iftop_](http://freecode.com/projects/iftop)

**Based on Various Protocols:** Using different protocols For example, SYN Flood, ICMP Flood, UDP flood

```
# tshark -r <FILE NAME>.pcap -q -z io,phs
# tshark -c 1000 -q -z io,phs
# tcpdump -tnr $FILE | awk -F '. ' '{print $1","$2"."$3","$4}' | sort | uniq -c | sort -n | tail
# tcpdump -qnn "tcp[tcpflags] & (tcp-syn) != 0"
# netstat -s
```

For example, it targets only one protocol

```
# tcpdump -nn not arp and not icmp and not udp
# tcpdump -nn tcp
```

**Connection State:** For example, the firewall can manage 10,000 concurrent connections, and the attacker sends 20,000

```
# netstat -n | awk '{print $6}' | sort | uniq -c | sort -nr | head
```

**Applications: Layer 7 Attacks** For example, HTTP GET flood, for high-volume image files.

```
# tshark -c 10000 -T fields -e http.host | uniq -c | sort -r | head -n 10
# tshark -r capture6 -T fields -e http.request.full_uri | sort | uniq -c | sort -r | head -n 10
# tcpdump -n 'tcp[32:4] = 0x47455420' | cut -f 7- -d ":"
```

For example, requests for archive files, GIF, ZIP, JPEG, PDF, PNG are unusual.

```
# tshark -Y "http contains \"ff:d8\"" || "http contains \"GIF89a\"" || "http contains \"\x50\x4B\x03\x04\"" || "http contains\xff\xd8" " || "http contains \"%PDF\"" || "http contains \"\x89\x50\x4E\x47\""
```

For example, pay attention and review the ‘user-agent’ amount in the web request.

```
# tcpdump -c 1000 -Ann | grep -Ei 'user-agent' | sort | uniq -c | sort -nr | head -10
```

For example, check the requested source headers.

```
# tcpdump -i en0 -A -s 500 | grep -i refer
```

Review HTTP requests to identify suspicious or dangerous patterns:

```
# tcpdump -s 1024 -l -A dst <EXAMPLE.COM>
```

**Poisoning or Poison: Layer 2 Attacks** For example, ARP poison, race condition DNS, DHCP

```
# tcpdump 'arp or icmp'
# tcpdump -tnr <SAMPLE TRAFFIC FILE>.pcap ARP | awk -F ',' '{print $1"."$2","$3","$4}' | sort | uniq -c | sort -n | tail
# tshark -r <SAMPLE TRAFFIC FILE>.pcap -q -z io,phs | grep arp.duplicate-address-detected
```

**Toolset** Prepared Machines and Operating Systems

**KALI** - Open Source Pentesting Distribution _Source:_ [_https://www.kali.org_](https://www.kali.org/)

**SIFT** - SANS Investigative Forensics Toolkit _Source:_ [_http://sift.readthedocs.org/_](http://sift.readthedocs.org/)

**REMNUX** - A Linux Toolkit for Reverse-Engineering and Analyzing Malware _Source:_ [_https://remnux.org_](https://remnux.org/)

**OPEN VAS** - Open Source vulnerability scanner and manager _Source:_ [_http://www.openvas.org_](http://www.openvas.org/)

**MOLOCH** - Large scale IPv4 packet capturing (PCAP), indexing and database system _Source:_ [_https://github.com/aol/moloch/wiki_](https://github.com/aol/moloch/wiki)

**SECURITY ONION** - Linux distro for intrusion detection, network security monitoring, and log management _Source:_ [_https://security-onionsolutions.github.io/security-onion/_](https://security-onionsolutions.github.io/security-onion/)

**NAGIOS** - Network Monitoring, Alerting, Response, and Reporting Tool _Source:_ [_https://www.nagios.org_](https://www.nagios.org/)

**OSSEC** - Scalable, multi-platform, open source Host-based Intrusion Detection System _Source:_ [_http://ossec.github.io_](http://ossec.github.io/)
