# eventvwr

#### **Cheatsheet** <a href="#cheatsheet" id="cheatsheet"></a>

**1. Opening Event Viewer**

* Use `eventvwr.msc` from the Run dialog or search for "Event Viewer" in the Start menu.

**2. Filtering Events**

* Use the "Filter Current Log" option to narrow down events based on criteria like Event ID, Keywords, etc.

**3. Creating Custom Views**

* Use "Create Custom View" to save specific filters for quick access.

**4. Exporting Logs**

* Use the "Save All Events As" option to export logs in various formats (e.g., CSV, XML).

**5. Clearing Logs**

* Use the "Clear Log" option to delete all events from a specific log.

**6. Attaching Tasks to Events**

* Use the "Attach Task To This Event" option to perform specific actions when an event occurs.

**7. Using Event Viewer with PowerShell**

* Leverage PowerShell cmdlets like `Get-EventLog` and `Get-WinEvent` to query and manage event logs.

**8. Understanding Event Levels**

* Familiarize yourself with event levels (Information, Warning, Error, etc.) to prioritize investigations.

**9. Understanding Event Sources**

* Identify the source of events to understand which application or component logged them.

**10. Analyzing Event Details**

* Dive into the "Details" tab of an event to understand its specifics and troubleshoot effectively.

#### Event IDs in Microsoft Event Viewer <a href="#event-ids-in-microsoft-event-viewer" id="event-ids-in-microsoft-event-viewer"></a>

**1. Event ID 4624: Successful Logon**

* Indicates a user successfully logged on to a computer.

**2. Event ID 4625: Logon Failure**

* Indicates a failed logon attempt.

**3. Event ID 4634: Logoff**

* Indicates a user logoff.

**4. Event ID 4648: Explicit Credential Logon**

* Indicates a logon using explicit credentials.

**5. Event ID 4663: File/Directory Access**

* Indicates an attempt to access a file or directory.

**6. Event ID 4672: Special Privileges Assigned**

* Indicates special privileges assigned to a new logon.

**7. Event ID 4688: Process Start**

* Indicates a new process creation.

**8. Event ID 4689: Process End**

* Indicates a process termination.

**9. Event ID 4698: Scheduled Task Created**

* Indicates a scheduled task was created.

**10. Event ID 4700: Scheduled Task Enabled**

* Indicates a scheduled task was enabled.

**11. Event ID 4719: System Audit Policy Change**

* Indicates a change in audit policy.

**12. Event ID 4720: User Account Created**

* Indicates a user account was created.

**13. Event ID 4722: User Account Enabled**

* Indicates a user account was enabled.

**14. Event ID 4725: User Account Disabled**

* Indicates a user account was disabled.

**15. Event ID 4738: User Account Changed**

* Indicates a user account was changed.

**16. Event ID 4740: User Account Locked Out**

* Indicates a user account was locked out.

**17. Event ID 4776: Credential Validation**

* Indicates a domain controller attempted to validate credentials.

**18. Event ID 4798: User Account Query**

* Indicates a query was issued for a user account.

**19. Event ID 4904: Security Auditing Setting Modification**

* Indicates an attempt to modify the per-user auditing settings.

**20. Event ID 4946: Windows Firewall Rule Added**

* Indicates a new Windows Firewall rule was added.

#### Example PowerShell Commands <a href="#example-powershell-commands" id="example-powershell-commands"></a>

**Query Specific Event ID**

```
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4624} -MaxEvents 10
```

**Query Events within a Date Range**

```
Get-WinEvent -FilterHashtable @{LogName='Security'; StartTime='MM/DD/YYYY 00:00:00'; EndTime='MM/DD/YYYY 23:59:59'}
```

**Query Events from a Specific Log Source**

```
Get-WinEvent -FilterHashtable @{LogName='Security'; ProviderName='Microsoft-Windows-Security-Auditing'}
```
