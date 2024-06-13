# Respond Analysis

**Analysis: LIVE TRIAGE - Windows**

**System Information:**

```
echo %DATE% %TIME%
hostname
systeminfo
systeminfo | findstr /B /C:"OS Name" /C:"OS Version"
wmic csproduct get name
wmic bios get serialnumber
wmic computersystem list brief
```

These commands are used to retrieve information about the system, including the date, time, hostname, detailed system info, operating system name and version, product name, BIOS serial number, and a brief list of computer systems.

**Source:** [https://technet.microsoft.com/en-us/sysinternals/psinfo.aspx](https://technet.microsoft.com/en-us/sysinternals/psinfo.aspx)

```
psinfo -accepteula -s -h -d
```

This command retrieves detailed system information using the `psinfo` tool from Sysinternals.

**User Information:**

```
whoami
net users
net localgroup administrators
net group administrators
wmic rdtoggle list
wmic useraccount list
wmic group list
wmic netlogin get name, lastlogon, badpasswordcount
wmic netclient list brief
doskey /history > history.txt
```

These commands gather information regarding the user, like the current user, all user accounts, group and local group administrators, remote desktop settings, and user account details. It also retrieves command line history and saves it to a text file.

**Network Information:**

```
netstat -e
netstat -naob
netstat -nr
netstat -vb
nbtstat -s
route print
arp -a
ipconfig /displaydns
netsh winhttp show proxy
ipconfig /allcompartments /all
netsh wlan show interfaces
netsh wlan show all
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Connections\WinHttpSettings"
type %SYSTEMROOT%\system32\drivers\etc\hosts
wmic nicconfig get descriptions, IPaddress, MACaddress
wmic netuse get name, username, connectiontype, localname
```

These commands collect various network-related information like network statistics, active connections, routing tables, ARP tables, DNS cache content, proxy settings, interface configurations, and more.

**Service Information:**

```
at
tasklist
tasklist /SVC
tasklist /SVC /fi "imagename eq svchost.exe"
schtasks
net start
sc query
wmic service list brief | findstr "Running"
wmic service list config
wmic process list brief
wmic process list status
wmic process list memory
wmic job list brief
```

PowerShell commands for service information:

```
Get-Service | Where-Object { $_.Status -eq "running" }
Get-Process | Select-Object Modules | ForEach-Object { $_.Modules }
```

These commands display information related to system tasks, services, and processes that are running, including service configuration and memory usage of processes.

**Policy, Patch, and Settings Information:**

```
set
gpresult /r
gpresult /z > [OUTPUT FILE NAME].txt
gpresult /H report.html /F
wmic qfe
```

For listing GPO-installed software:

```
reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Group Policy\AppMgmt"
```

These commands are used to display the environment variable, group policy results, and Quick Fix Engineering (update patches) information.

**Autorun and Autoload Information:**

```
wmic startup list full
wmic ntdomain list brief
```

Commands to display the content of the startup service path:

```
dir "%SystemDrive%\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
dir "%SystemDrive%\Documents and Settings\All Users\Start Menu\Programs\Startup"
dir %userprofile%\Start Menu\Programs\Startup
dir %ProgramFiles%\Startup\
dir C:\Windows\Start Menu\Programs\startup
dir "C:\Users\%username%\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup"
dir "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
dir "%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup"
dir "%ALLUSERSPROFILE%\Microsoft\Windows\Start Menu\Programs\Startup"
dir "%ALLUSERSPROFILE%\Start Menu\Programs\Startup"
type C:\Windows\winstart.bat
type %windir%\wininit.ini
type %windir%\win.ini
```

Showing Microsoft autorun and hidden files **Source:** [https://technet.microsoft.com/en-us/sysinternals/bb963902.aspx](https://technet.microsoft.com/en-us/sysinternals/bb963902.aspx)

```
autorunsc -accepteula -m
type C:\Autoexec.bat
```

Commands to display and save all autorun files in CSV and check them using virustotal:

```
autorunsc.exe -accepteula -a -c -i -e -f -l -m -v
```

Commands querying registry entries:

```
reg query HKCR\Comfile\Shell\Open\Command
reg query HKCR\Batfile\Shell\Open\Command
reg query HKCR\htafile\Shell\Open\Command
reg query HKCR\Exefile\Shell\Open\Command
reg query HKCR\Exefiles\Shell\Open\Command
reg query HKCR\piffile\shell\open\command
```

**HKEY\_CURRENT\_USERS:**

Commands for querying various registry keys under the HKEY\_CURRENT\_USER hive:

```
C:\> reg query HKCU\Control Panel\Desktop
C:\> reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run
C:\> reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Run
C:\> reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Runonce
C:\> reg query HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnceEx
C:\> reg query HKCU\Software\Microsoft\Windows\CurrentVersion\RunServices
C:\> reg query HKCU\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce
C:\> reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Windows\Run
C:\> reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Windows\Load
... (and so on)
```

**HKEY\_LOCAL\_MACHINE:**

Commands querying registry keys under the HKEY\_LOCAL\_MACHINE hive:

```
C:\> reg query HKLM\SOFTWARE\Microsoft\ActiveSetup\Installed Components" /s
C:\> reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\explorer\User Shell Folders"
C:\> reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\explorer\Shell Folders"
C:\> reg query HKLM\Software\Microsoft\Windows\CurrentVersion\explorer\ShellExecuteHooks
... (and so on)
```

**LOGS**

Commands related to working with event logs, including exporting logs:

```
C:\> wevtutil epl Security C:\<BACK UP PATH>\mylogs.evtx
C:\> wevtutil epl System C:\<BACK UP PATH>\mylogs.evtx
C:\> wevtutil epl Application C:\<BACK UP PATH>\mylogs.evtx
```

**Alternate Data Streams:**

[https://technet.microsoft.com/en­](https://technet.microsoft.com/en%C2%AD)-us/sysinternals/streams.aspx

```
C:\> streams -s <FILE OR DIRECTORY>
```

**check malicious file and save in csv**

منبع. [https://technet.microsoft.com/en­](https://technet.microsoft.com/en%C2%AD) us/sysinternals/bb897441.aspx

```
C:\> sigcheck -c -h -s -u -nobanner <FILE OR
DIRECTORY> > <OUTPUT FILENAME>,csv
```

**check malicious file**

```
C:\> sigcheck -e -u -vr -s C:\
```

DLL Unassigned

[https://technet.microsoft.com/en­](https://technet.microsoft.com/en%C2%AD)-us/sysinternals/bb896656.aspx

```
C:\> listdlls.exe -u
C:\> listdlls.exe -u <PROCESS NAME OR PID>
```

**Windows Defender**

منبع. [http://windows.microsoft.com/en­](http://windows.microsoft.com/en%C2%AD)-us/windows/what-is-windows-defender-offline

```
C:\> MpCmdRun.exe -SignatureUpdate
C:\> MpCmdRun.exe -Scan
```

LIVE TRIAGE - Linux

**System Information**

```
# uname -a
# uptime
# timedatectl
# mount
```

**User Information**

* List of users who have logged in:
* List of users who have logged in remotely:
* Show unsuccessful logins:
* Display local users:

```
# cat /etc/passwd
# cat /etc/shadow
```

* Display local groups:
* Display sudo access:
* Display users with UID 0:

```
# awk -F: '($3 == "0") {print}' /etc/passwd
# egrep ':0+' /etc/passwd
```

* List of valid ssh authentication keys:

```
# cat /root/.ssh/authorized_keys
```

* List files opened by the user:
* Display bash history:

```
# cat /root/.bash_history
```

**Network Information**

* Display network interfaces:
* Display network connections:

```
# netstat -antup
# netstat -plantux
```

* Display listening ports:
* Display routes:
* Display the ARP table:
* Display processes and used ports list:

**Service Information**

* List of processes:
* List of loaded modules:
* List of open files:
* List of network-open files:

```
# lsof -nPi | cut -f 1 -d " " | uniq | tail -n +2
```

* List of files opened by a specific process:
* List of all files opened by a specific process:
* List of unlinked processes’ keys in execution:
* Processes of a PID:
* Storing analysis of executable files of malware:

```
# cp /proc/<PID>/exe /<SUSPICIOUS FILE NAME TO SAVE>.elf
```

* Live reports display:

```
# less +F /var/log/messages
```

* List of services:

**Policy, Patch, and Settings Information**

* Display files within the pam.d path:

**Autorun and Autoload Information**

* List of cron jobs:
* List of cron jobs run by root user and UID zero:
* Check unusual cron jobs:

```
# cat /etc/crontab
# ls /etc/cron.*
```

**Reports**

* Check history of executed commands by root user:
* Check the last user logged into the system:

**Files, Drivers, and Shared Environment Information**

* Display disk usage:
* Display files in /etc/init.d path:
* More information about a file:
* Determine file type:
* Display immutable files:

```
# lsattr -R / | grep -i "-"
```

* List files in /root path:
* Display a list of recently modified files:
* List writable files:

```
# find / -xdev -type d \( -perm -0002 -a ! -perm -1000 \) -print
```

* List files created since Jan 02, 2017:

```
# find / -newermt 2017-01-02
```

* List all files and their attributes:

```
# find / -printf "%m;%Ax;%AT;%Tx;%TT;%Cx;%CT;%U;%G;%s;%p\n"
```

* List files in a specific path that have a newer timestamp (might be manipulated):

```
# ls -alt /<DIRECTORY> | head
```

* Display file details:

```
# stat /<FILE PATH>/<SUSPICIOUS FILE NAME>
```

* Check file type:

```
# file /<FILE PATH>/<SUSPICIOUS FILE NAME>
```

**Run unix-privsec-check tool:**

```
# wget https://raw.githubusercontent.com/pentestmonkey/unix-privesc-check/1_x/unix-privesc-check
# ./unix-privesc-check > output.txt
```

**Execute chkrootkit:**

```
# apt-get install chkrootkit
# chkrootkit
```

**Execute rkhunter:**

```
# apt-get install rkhunter
# rkhunter --update
# rkhunter --check
```

**Execute tiger:**

```
# apt-get install tiger
# tiger
# less /var/log/tiger/security.report.*
```

**Execute lynis:**

```
# apt-get install lynis
# lynis audit system
# more /var/logs/lynis.log
```

**Execute Linux Malware Detect (LMD):**

```
bashCopy code# wget http://www.rfxn.com/downloads/maldetect-current.tar.gz
# tar xfz maldetect-current.tar.gz
# cd maldetect-*
# ./install.sh
```

**Get LMD updates:**

**Run and scan LMD on a specific path:**

**USB Examination:**

**Displaying Events using usbrip:**

```
usbrip events violations auth.json
```

**Git Analysis:**

**Display history:**

**Display commit contents:**

```
git checkout <commit> --force
```

**MALWARE Analysis:**

**STATIC ANALYSIS:**

**Creating Mount live Sysinternals tools drive:**

```
\\live.sysinternals.com\tools
```

**Checking Signature for dlt and exe files:**

Source: [http://technet.microsoft.com/en-us/sysinternals/bb897441.aspx](http://technet.microsoft.com/en-us/sysinternals/bb897441.aspx)

```
C:\> sigcheck.exe -u -e (:\<DIRECTORY>
C:\> sigcheck.exe -vt <SUSPICIOUS FILE NAME>
```

**Shell Codes Analysis:**

[Read More:](http://sandsprite.com/CodeStuff/scdbg\_manual/MANUAL\_EN.html)

**Windows PE Analysis:**

**Display Hex and ASCI of PE files (exe or any file), with switch -n and first 500 bytes:**

```
# hexdump -C -n 500 <SUSPICIOUS FILE NAME>
# od -x somefile.exe
# xxd somefile.exe
```

**Use debug tool in Windows (for .java files):**

```
C:\> debug <SUSPICIOUS FILE NAME>
> -d 
> -q 
```

**Windows PE Analysis:**

Script for compile time and date of PE files (Only for Windows). Source: [https://www.perl.org/get.html](https://www.perl.org/get.html) and [http://www.perlmonks.org/bare/?node\_id=484287](http://www.perlmonks.org/bare/?node\_id=484287)

```
C:\> perl.exe <SCRIPT NAME>.pl <SUSPICIOUS FILE NAME>
```

**Displaying strings inside PE and string lengths with switch -n:**

Using strings in Linux:

```
# strings -n 10 <SUSPICIOUS FILE NAME>
```

Source: [https://technet.microsoft.com/en-us/sysinternals/strings.aspx](https://technet.microsoft.com/en-us/sysinternals/strings.aspx)

Using strings in Windows:

```
C:\> strings <SUSPICIOUS FILE NAME>
```

**Identify Malware in dumped memory using Volatility and the Windows7SPFix64 profile:**

Source: [https://github.com/volatilityfoundation/volatility](https://github.com/volatilityfoundation/volatility)

```
# python vol.py -f <MEMORY DUMP FILE NAME>.raw --profile=Win7SPFix64 malfind -D /<OUTPUT DUMP DIRECTORY>
# python vol.py -f <MEMORY DUMP FILE NAME>.raw --profile=Win7SPFix64 malfind -p <PID #> -D /<OUTPUT DUMP DIRECTORY>
# python vol.py -f <MEMORY DUMP FILE NAME>.raw --profile=Win7SPFix64 pslist
# python vol.py -f <MEMORY DUMP FILE NAME>.raw --profile=Win7SPFix64 pstree
# python vol.py -f <MEMORY DUMP FILE NAME>.raw --profile=Win7SPFix64 dlllist
# python vol.py -f <MEMORY DUMP FILE NAME>.raw --profile=Win7SPFix64 dlldump -D /<OUTPUT DUMP DIRECTORY>
```

**Process memory output**

```
volatility -f flounder-pc-memdump.elf --profile=<PROFILE> memdump -p <PID> -D dump
```

**Malware Checking and Identification Tool:**

Source: [https://github.com/Defense-Cyber-Crime-Center/DC3-MWCP](https://github.com/Defense-Cyber-Crime-Center/DC3-MWCP)

**Installing dc3-mwcp tool:**

**Using dc3-mwcp tool to check suspicious files:**

```
mwcp-tool.py -p <SUSPICIOUS FILE NAME>
```

**MALWARE IDENTIFICATION**

* Tool: PROCESS EXPLORER
*

**Step 1: Process Listing and Inspecting Suspicious Items:**

```
No icon items
- No description or company name items
- Unsigned Microsoft images
- Check hashes in Virus Total
- Suspicious files in Windows directories or user profile
- Purple items (packed or compressed)
- Items with open TCP/IP endpoints
```

**Step 2: Checking File Signatures:**

**Step 3: Examining Strings:**

```
Investigate suspicious URLs in strings.
```

**Step 4: Viewing DLLs:**

```
Use Ctrl+D to pop open
- Inspect for suspicious DLLs or services
```

**Step 5: Stopping and Removing Malware:**

```
Suspend and terminate suspicious processes
```

**Step 6: Remove suspicious files that run at system startup:**

**Step 7: Process Monitoring**

**Step 8: Repeat Above Steps for Identifying Suspicious Files.**

**Check File Hashes**

**Utilizing VirusTotal APIs:**

```
# Submitting suspicious file hashes to virustotal using curl:
curl -v --request POST --url https://www.virustotal.com/vtapi/v2/file/report' -d apikey=[VT API KEY] -d 'resource=[SUSPICIOUS FILE HASH]'

# Submitting suspicious files to virustotal using curl:
curl -v -F 'file=[PATH TO FILE]/[SUSPICIOUS FILE NAME]' -F apikey=[VT API KEY] https://www.virustotal.com/vtapi/v2/file/scan
```

**Utilizing Team Cymru APIs:**

```
# Check malware hashes using Team Cymru and whois tool:
whois -h hash.cymru.com [SUSPICIOUS FILE HASH]
```

**HARD DRIVE AND MEMORY ACQUISITION**

* OS: WINDOWS
* Remotely create a memory dump:

```
C:\> psexec.exe \\<HOST NAME OR IP ADDRESS> -u <DOMAIN>\<PRIVILEGED ACCOUNT> -p <PASSWORD> -c mdd_l,3.exe --o C:\memory.dmp
```

* Extract exe and dll files from dumped memory:

```
C:\> volatility dlldump -f memory.dmp -0 dumps/
C:\> volatility procmemdump -f memory.dmp -0 dumps/
```

* OS: LINUX
* Create a memory dump:

```
dd if=/dev/fmem of=/tmp/[MEMORY FILE NAME].dd
```

**Investigate Hidden Data in Files and Pictures**

* Utilizing various websites and tools like dcode, StegCracker, StegExtract, Sonic Visualizer, spek, etc.

Create a memory dump using LiME tool: Source: [https://github.com/504ensicslabs/lime](https://github.com/504ensicslabs/lime)

```
# wget
wget https://github.com/504ensicslabs/LiME/archive/master.zip
unzip master.zip
# cd LiME-master/src
cd LiME-master/src
# make
make
# cp lime-*,ko /media/=/media/ExternalUSBDriveName/
cp lime-*.ko /media/ExternalUSBDriveName/
# insmod lime-3.13.0-79-generic.ko "path=/media/ExternalUSBDriveName/<MEMORY DUMP>, lime format= raw"
insmod lime-3.13.0-79-generic.ko "path=/media/ExternalUSBDriveName/<MEMORY DUMP>, lime format= raw"
```

Create a copy of a suspicious process using process ID:

```
# cp /proc/<SUSPICIOUS PROCESS ID>/exe /<NEW SAVED LOCATION>
cp /proc/<SUSPICIOUS PROCESS ID>/exe /<NEW SAVED LOCATION>
```

More information about the suspicious process in dumped memory:

```
# gcore <PID>
gcore <PID>
```

Using Strings on a file:

```
# strings gcore.*
strings gcore.*
```

Create a copy of a hard drive and partition including tags and hashes:

```
# dd if=<INPUT DEVICE> of=<IMAGE FILE NAME>
dd if=<INPUT DEVICE> of=<IMAGE FILE NAME>
# dc3dd if=/dev/<TARGET DRIVE EXAMPLE SDA OR SDA1> of=/dev/<MOUNTED LOCATION>/<FILE NAME>.img hash=md5 log=/<MOUNTED LOCATION>/<LOG NAME>.log
dc3dd if=/dev/<TARGET DRIVE EXAMPLE SDA OR SDA1> of=/dev/<MOUNTED LOCATION>/<FILE NAME>.img hash=md5 log=/<MOUNTED LOCATION>/<LOG NAME>.log
```

Create a hard drive and partition over SSH:

```
# dd if=/dev/<INPUT DEVICE> | ssh <USERNAME>@<DESTINATION IP ADDRESS> "dd of=<DESTINATION PATH>"
dd if=/dev/<INPUT DEVICE> | ssh <USERNAME>@<DESTINATION IP ADDRESS> "dd of=<DESTINATION PATH>"
```

Send a zipped hard drive image over netcat: To send to the host:

```
# bzip2 -c /dev/<INPUT DEVICE> | nc <DESTINATION IP ADDRESS> <PICK A PORT>
bzip2 -c /dev/<INPUT DEVICE> | nc <DESTINATION IP ADDRESS> <PICK A PORT>
```

To receive by the host:

```
# nc -p <PICK SAME PORT> -l | bzip2 -d | dd of=/dev/sdb
nc -p <PICK SAME PORT> -l | bzip2 -d | dd of=/dev/sdb
```

To send to host host:

```
# dd if=/dev/<INPUT DEVICE> bs=16M | nc <PORT>
dd if=/dev/<INPUT DEVICE> bs=16M | nc <PORT>
```

To receive by the host using Pipe Viewer meter:

```
# nc -p <SAME PORT> -l -vv | pv -r | dd of=/dev/<INPUT DEVICE> bs=16M
nc -p <SAME PORT> -l -vv | pv -r | dd of=/dev/<INPUT DEVICE> bs=16M
```

Encryption websites:

Examining hidden data in a file with StegCracker: [https://github.com/Paradoxis/StegCracker](https://github.com/Paradoxis/StegCracker) Example:

Examining hidden data in a photo with bash script StegExtract:

```
sudo curl https://raw.githubusercontent.com/evyatarmeged/stegextract/master/stegextract > /usr/local/bin/stegextract
sudo chmod +x /usr/local/bin/stegextract
```

Example:

```
stegextract simple.gif --analysis --string
```

Examining hidden data in a photo with StegSolve:

```
wget http://www.caesum.com/handbook/Stegsolve.jar -O stegsolve.jar
chmod +x stegsolve.jar
java -jar stegsolve.jar
```

Examining hidden data in a file with exiftool:

```
sudo apt-get install libimage-exiftool-perl
```

Example:

```
exiftool poissonrecon.pdf
```

Examining hidden data in music with Sonic Visualizer: [https://www.sonicvisualiser.org/download.html](https://www.sonicvisualiser.org/download.html) Example: In Sonic Visualizer, select: Pane -> Add Spectrogram -> Channel 1

Examining hidden data in music with spek:

### Powershell Investigation <a href="#powershell-investigation" id="powershell-investigation"></a>

Investigating PowerShell activity can be crucial in modern cybersecurity due to PowerShell's powerful capabilities and its frequent use in various attack scenarios. PowerShell is a versatile scripting language that provides vast access to a system's internals, making it a potent tool for both system administrators and adversaries. Hence, monitoring PowerShell execution is essential for detecting potential malicious activities.

Here's how the Windows Event IDs 4103 and 4104 pertain to PowerShell investigation:

1. **Event ID 4103: PowerShell Script Block Logging**:
   * Event ID 4103 is associated with PowerShell Script Block Logging, which is a feature that logs the processing of PowerShell commands and scripts. This logging includes the script block contents, even if they are obfuscated or encrypted, providing insight into exactly what code was run.
   * By analyzing the logs associated with this Event ID, investigators can examine the PowerShell commands/scripts executed on a system. This can be invaluable in understanding the actions taken by an adversary or troubleshooting legitimate script-related issues.
2. **Event ID 4104: PowerShell Module Logging**:
   * Event ID 4104 is related to PowerShell Module Logging, which logs pipeline execution details, including the names of cmdlets, functions, workflows, and scripts involved, along with their parameters.
   * Similar to script block logging, module logging helps investigators understand the sequence of PowerShell operations and the context in which they were run. This can be instrumental in identifying malicious PowerShell usage or troubleshooting legitimate operations.

Both Event IDs 4103 and 4104 are part of a broader PowerShell logging capability that, when properly configured and monitored, can significantly aid in the investigation of malicious activities or system issues. Collecting and analyzing these logs can provide a wealth of information about the actions being performed on a system via PowerShell, making them a crucial aspect of PowerShell-related investigations.

### Registry run keys <a href="#registry-run-keys" id="registry-run-keys"></a>

### Logon Type <a href="#logon-type" id="logon-type"></a>

#### Logon Failure <a href="#logon-failure" id="logon-failure"></a>

#### Common failure code <a href="#common-failure-code" id="common-failure-code"></a>

#### Account management events <a href="#account-management-events" id="account-management-events"></a>

#### Addition or removal of a member events <a href="#addition-or-removal-of-a-member-events" id="addition-or-removal-of-a-member-events"></a>

#### Security group creation and removal events <a href="#security-group-creation-and-removal-events" id="security-group-creation-and-removal-events"></a>

### Process Anatomy <a href="#process-anatomy" id="process-anatomy"></a>

1. **Process name: lsass.exe**
   * Process path: `%Systemroot%\System32\lsass.exe`
   * Username: SYSTEM
   * Number of instances: One
   * Parent process: `wininit.exe`
2. **Process name: smss.exe**
   * Process path: `%Systemroot%\System32\smss.exe`
   * Username: SYSTEM
   * Number of instances: One
   * Parent process: `System`
3. **Process name: csrss.exe**
   * Process path: `%Systemroot%\System32\csrss.exe`
   * Username: SYSTEM
   * Number of instances: Two (one for system processes and one for user processes)
   * Parent process: `smss.exe`
4. **Process name: wininit.exe**
   * Process path: `%Systemroot%\System32\wininit.exe`
   * Username: SYSTEM
   * Number of instances: One
   * Parent process: `smss.exe`
5. **Process name: services.exe**
   * Process path: `%Systemroot%\System32\services.exe`
   * Username: SYSTEM
   * Number of instances: One
   * Parent process: `wininit.exe`
6. **Process name: svchost.exe**
   * Process path: `%Systemroot%\System32\svchost.exe`
   * Username: Varies (can run as SYSTEM, NETWORK SERVICE, LOCAL SERVICE, etc.)
   * Number of instances: Multiple (one for each group of services)
   * Parent process: `services.exe`
7. **Process name: RuntimeBroker.exe**
   * Process path: `%Systemroot%\System32\RuntimeBroker.exe`
   * Username: The user's account
   * Number of instances: Multiple
   * Parent process: `svchost.exe`
8. **Process name: winlogon.exe**
   * Process path: `%Systemroot%\System32\winlogon.exe`
   * Username: SYSTEM
   * Number of instances: One for each interactive user login
   * Parent process: `smss.exe`
9. **Process name: LogonUI.exe**
   * Process path: `%Systemroot%\System32\LogonUI.exe`
   * Username: SYSTEM
   * Number of instances: One (when required for user logon interactions)
   * Parent process: `winlogon.exe`
10. **Process name: explorer.exe**
    * Process path: `%Systemroot%\explorer.exe`
    * Username: The user's account
    * Number of instances: One per user session
    * Parent process: `userinit.exe` or `winlogon.exe` (depending on the system configuration)

Event ID 4688 records every process creation activity

Event ID 4689 records every process exit activity

#### Process integrity values for Mandatory Labe <a href="#process-integrity-values-for-mandatory-labe" id="process-integrity-values-for-mandatory-labe"></a>

#### Windows processes <a href="#windows-processes" id="windows-processes"></a>

#### &#x20;<a href="#echotrail" id="echotrail"></a>

#### &#x20;<a href="#lolbas" id="lolbas"></a>
