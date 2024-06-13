# Sysmon

#### **Cheatsheet** <a href="#cheatsheet" id="cheatsheet"></a>

**1. Install Sysmon**

* Ensure Sysmon is installed to monitor and log system activity.

**2. Configure Sysmon**

* Use an XML configuration file to define what events Sysmon should log.

**3. Update Sysmon**

* Update Sysmon to the latest version to leverage new features and fixes.

**4. Uninstall Sysmon**

* Remove Sysmon from the system when it's no longer needed.

**5. Sysmon Event Logging**

* Understand the different event IDs and what they represent.

**6. Sysmon Filtering**

* Implement filtering in the configuration to reduce noise.

**7. Sysmon with SIEM**

* Integrate Sysmon logs with SIEM solutions for analysis and correlation.

**8. Sysmon Schema**

* Understand the schema of Sysmon logs to create effective queries and alerts.

**9. Sysmon and PowerShell**

* Leverage PowerShell for Sysmon installation, configuration, and log querying.

**45 Real Examples for Sysmon**

**1-9: Sysmon Event IDs and Their Significance**

1. **Event ID 1: Process Creation**
   * Logs when a process is created and includes the command line.
2. **Event ID 2: File creation time**
   * Logs changes in file creation timestamps.
3. **Event ID 3: Network Connection**
   * Logs when a process makes an outbound network connection.
4. **Event ID 4: Sysmon Service State Change**
   * Logs changes in the Sysmon service state.
5. **Event ID 5: Process Termination**
   * Logs when a process terminates.
6. **Event ID 6: Driver Loaded**
   * Logs when a driver is loaded.
7. **Event ID 7: Image Loaded**
   * Logs DLLs and other images loaded into a process.
8. **Event ID 8: CreateRemoteThread**
   * Logs when a thread is created in another process.
9. **Event ID 9: RawAccessRead**
   * Logs when a process reads sectors from disk volume.

**10-18: Sysmon Commands and Usage**

1.
2.  **Install with Configuration**

    ```
    Sysmon.exe -i sysmonconfig.xml
    ```
3.  **Update Sysmon Configuration**

    ```
    Sysmon.exe -c sysmonconfig.xml
    ```
4.
5.  **Dump Sysmon Configuration**

    ```
    shellCopy codeSysmon.exe -c
    ```
6.
7.
8. **Extract Sysmon Configuration**
9.  **Log to a Different Event Log**

    ```
    Sysmon.exe -i -l <LogName>
    ```

**19-45: Sysmon Configuration Examples**

19-45. **Sysmon Configuration Examples** - Below is a sample Sysmon configuration XML snippet. A full configuration would typically contain multiple entries under each event type to define what should be logged and what should be excluded.

```
<Sysmon schemaversion="4.50">
    <!-- Capture all processes -->
    <EventFiltering>
        <ProcessCreate onmatch="exclude">
            <Image condition="is">C:\Windows\System32\svchost.exe</Image>
        </ProcessCreate>
        <!-- Exclude network connections to Microsoft IPs -->
        <NetworkConnect onmatch="exclude">
            <DestinationIp condition="is">13.107.4.50</DestinationIp>
        </NetworkConnect>
        <!-- Log all other network connections -->
        <NetworkConnect onmatch="include" />
        <!-- Log DLLs loaded into lsass.exe -->
        <ImageLoad onmatch="include">
            <Image condition="image">lsass.exe</Image>
        </ImageLoad>
        <!-- Exclude certain drivers -->
        <DriverLoad onmatch="exclude">
            <Signature condition="contains">Microsoft</Signature>
        </DriverLoad>
        <!-- Log other drivers -->
        <DriverLoad onmatch="include" />
    </EventFiltering>
</Sysmon>
```

#### Top Sysmon Event IDs <a href="#top-sysmon-event-ids" id="top-sysmon-event-ids"></a>

**1. Event ID 1: Process Creation**

* Logs when a process is created and includes the command line.

**2. Event ID 2: File Creation Time Changed**

* Logs changes in file creation timestamps.

**3. Event ID 3: Network Connection**

* Logs when a process makes an outbound network connection.

**4. Event ID 4: Sysmon Service State Change**

* Logs changes in the Sysmon service state.

**5. Event ID 5: Process Terminated**

* Logs when a process terminates.

**6. Event ID 6: Driver Loaded**

* Logs when a driver is loaded.

**7. Event ID 7: Image Loaded**

* Logs DLLs and other images loaded into a process.

**8. Event ID 8: CreateRemoteThread**

* Logs when a thread is created in another process.

**9. Event ID 9: RawAccessRead**

* Logs when a process reads sectors from disk volume.

**10. Event ID 10: ProcessAccess**

* Logs when a process opens another process.

**11. Event ID 11: FileCreate**

* Logs when a file is created or overwritten.

**12. Event ID 12: RegistryEvent (Object create and delete)**

* Logs when a registry object is created or deleted.

**13. Event ID 13: RegistryEvent (Value Set)**

* Logs when a registry value is set.

**14. Event ID 14: RegistryEvent (Key and Value Rename)**

* Logs when a registry key or value is renamed.

**15. Event ID 15: FileCreateStreamHash**

* Logs when a named file stream is created.

**16. Event ID 16: Sysmon Config State Change**

* Logs when the Sysmon configuration is changed.

**17. Event ID 17: Pipe Created**

* Logs when a named pipe is created.

**18. Event ID 18: Pipe Connected**

* Logs when a named pipe is connected.

**19. Event ID 19: WmiEvent (WmiEventFilter activity detected)**

* Logs WMI event filter creation.

**20. Event ID 20: WmiEvent (WmiEventConsumer activity detected)**

* Logs WMI event consumer creation.
