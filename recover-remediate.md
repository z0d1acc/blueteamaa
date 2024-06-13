# Recover Remediate

**After the Attack**

**Implementation**

**Windows**

**Using a Hotfix Update for Windows 7 or above:**

```
C:\> wusa.exe C:\<PATH TO HOTFIX>\Windows6.0-KB934307-x86.msu
```

**Using a Hotfix Update for Windows 7 or above with a batch script:**

```
@echo off
setlocal
set PATHTOFIXES=E:\hotfix
%PATHTOFIXES%\Q123456_w2k_sp4_x86.exe /2 /M
%PATHTOFIXES%\Ql23321_w2k_sp4_x86.exe /2 /M
%PATHTOFIXES%\Q123789_w2k_sp4_x86.exe /2 /M
```

**Checking for Updates in Windows 7 or above:**

```
C:\> wuauclt.exe /detectnow /updatenow
```

**Linux**

**Ubuntu Distribution:**

* Fetching the update list:
* Upgrading current packages:
* Installing updates (new):

**Red Hat Enterprise Linux 2.1, 3, 4:**

```
# up2date
# up2date-nox --update
# up2date <PACKAGE NAME>
# up2date -u <PACKAGE NAME>
```

**Red Hat Enterprise Linux 5:**

**Red Hat Enterprise Linux 6:**

```
# yum update
# yum list installed <PACKAGE NAME>
# yum install <PACKAGE NAME>
# yum update <PACKAGE NAME>
```

**Kali Distribution:**

```
# apt-get update && apt-get upgrade
```

**Backup**

**Windows**

* Backup GPO Audit Policy to a CSV file:

```
C:\> auditpol /backup /file:C\auditpolicy.csv
```

* Restore GPO Audit Policy from a CSV file:

```
C:\> auditpol /restore /file:C:\auditpolicy.csv
```

* Back up all GPOs in the domain and store them in a specified location:

```
PS C:\> Backup-Gpo -All -Path \\<SERVER>\<PATH TO BACKUPS>
```

* Restore backup GPOs in the domain from a specified location:

```
PS C:\> Restore-GPO -All -Domain <INSERT DOMAIN NAME> -Path \\Serverl\GpoBackups
```

* Start the Volume Shadow service:
* List all shadow files and storage:

```
C:\> vssadmin List ShadowStorage
```

* List all shadow files:

```
C:\> vssadmin List Shadows
```

* Search Shadow Copy for files and folders:

```
C:\> mklink /d c:\<CREATE FOLDER>\<PROVIDE FOLDER NAME BUT DO NOT CREATE> \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopyl\
```

* Jump to the selected shadow file in Windows Server and Windows 8:

```
C:\> vssadmin revert shadow /shadow={<SHADOW COPY ID>} /ForceDismount
```

* Retrieve the history of previous versions of a file with `volrest.exe`:

```
C:\> "\Program Files (x86)\Windows Resource Kits\Tools\volrest.exe" "\\localhost\c$\<PATH TO FILE>\<FILE NAME>"
```

* Jump to a selected version of a file or @GMT using `volrest.exe`:

```
C:\> subst Z: \\localhost\c$\$\<PATH TO FILE>
C:\> "\Program Files (x86)\Windows Resource Kits\Tools\volrest.exe" "\\localhost\c$\<PATH TO FILE>\<CURRENT FILE NAME OR @GMT FILE NAME FROM LIST COMMAND ABOVE>" /R:Z:\
C:\> subst Z: /0
```

* Jump to another path or sub-path using `volrest.exe`:

```
C:\> "\Program Files (x86)\Windows Resource Kits\Tools\volrest.exe" \\localhost\c$\<PATH TO FOLDER\*.* /5 /r:\\localhost\c$\<PATH TO FOLDER>\
```

* Jump to the selected shadow file in Windows Server, Windows 7, and Windows 10 using `wmic`:

```
C:\> wmic shadowcopy call create Volume='C:\'
```

* Create a shadow copy of volume C on Windows 7 and Windows 10 using PowerShell:

```
PS C:\> (gwmi -list win32_shadowcopy).Create('C:\', 'ClientAccessible')
```

* Create a shadow copy of volume C on Windows Server 2003 and Windows Server 2008:

```
C:\> vssadmin create shadow /for=c:
```

* Create a restore point in Windows:

```
C:\> wmic.exe /Namespace:\\root\default Path SystemRestore Call CreateRestorePoint "%DATE%", 100, 7
```

* Recover to a restore point in Windows XP:

```
C:\> sc config srservice start= disabled
C:\> reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore" /v DisableSR /t REG_DWORD /d 1 /f
C:\> net stop srservice
```

* List recoverable points:

```
PS C:\> Get-ComputerRestorePoint
```

* Recover to a recoverable point:

```
PS C:\> Restore-Computer -RestorePoint <RESTORE POINT#> -Confirm
```

**Linux**

**Resetting the root user password in single-user mode:** Step 1: Reboot the system.

Step 2: Press the ESC key to enter the GRUB page.

Step 3: Select the default entry and press the e key to edit it.

Step 4: Look for a line that begins with the words linux, linux16, or linuxefi.

Step 5: Add ‘rw init=/bin/bash’ to the end of that line.

Step 6: Press the Ctrl-X key combination to boot.

Step 7: After rebooting, you should enter single-user mode as root and be able to change your password with the following command:

Step 8: Reboot the system again.

**Reinstalling Packages:**

```
# apt-get install --reinstall <COMPROMISED PACKAGE NAME>
```

Reinstall all packages:

```
# apt-get install --reinstall $(dpkg --get-selections | grep -v deinstall)
```

**Removing MALWARE Processes**

**Windows** Malware Removal Tool: Source: [http://www.gmer.net/](http://www.gmer.net/)

Removing a suspicious file that is running:

```
C:\> gmer.exe -killfile C:\WINDOWS\system32\drivers\<MALICIOUS FILENAME>.exe
```

Removing a suspicious running file in PowerShell:

```
PS C:\> Stop-Process -Name <PROCESS NAME>
PS C:\> Stop-Process -ID <PID>
```

**Linux** Terminate the malware process:

Disable the malware's executability and change its path:

```
# chmod -x /usr/sbin/<SUSPICIOUS FILE NAME>
# mkdir /home/quarantine/
# mv /usr/sbin/<SUSPICIOUS FILE NAME> /home/quarantine/
```

Terminate the application using a specific port:
