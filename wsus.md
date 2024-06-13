# WSUS

#### **Cheatsheet** <a href="#cheatsheet" id="cheatsheet"></a>

**1. Install WSUS**

* Open Server Manager -> Add roles and features -> WSUS

**2. Configure WSUS**

* Open WSUS -> Complete the Configuration Wizard

**3. Create Computer Groups**

* WSUS Console -> Computers -> Create a Computer Group

**4. Approve Updates**

* WSUS Console -> Updates -> Approve Updates

**5. Deploy WSUS to Clients**

* Group Policy -> Configure Update Source -> Point to WSUS Server

**6. Monitor Update Installations**

* WSUS Console -> Reports -> Update Status

**7. Manage WSUS Configurations**

* WSUS Console -> Options -> WSUS Server Configuration Wizard

**8. Synchronize Updates**

* WSUS Console -> Synchronizations -> Start Synchronization

**9. Cleanup WSUS**

* WSUS Console -> Options -> Server Cleanup Wizard

**10. Secure WSUS Communication**

```
Configure SSL on WSUS -> Update Group Policy for Secure Communication
```

#### Examples for Hardening with WSUS <a href="#examples-for-hardening-with-wsus" id="examples-for-hardening-with-wsus"></a>

**1. Install WSUS Role**

```
Install-WindowsFeature -Name UpdateServices -IncludeManagementTools
```

**2. Configure WSUS Post-Installation**

```
& "$env:ProgramFiles\Update Services\Tools\WsusUtil.exe" postinstall CONTENT_DIR=D:\WSUS
```

**3. Create a Computer Group in WSUS**

Navigate through WSUS Console -> Computers -> Add Computer Group -> Name: "SecureGroup"

**4. Approve Updates for a Group**

Navigate through WSUS Console -> Updates -> Select an Update -> Approve -> Select "SecureGroup"

**5. Configure WSUS on Clients via GPO**

* Open Group Policy Management -> Create a GPO -> Navigate to: Computer Configuration -> Policies -> Administrative Templates -> Windows Components -> Windows Update -> Configure Automatic Updates & Specify intranet Microsoft update service location -> Define WSUS Server

**6. Start WSUS Synchronization**

```
Get-WsusServer | Get-WsusSubscription | Start-WsusSynchronization
```

**7. Retrieve Update Status**

Navigate through WSUS Console -> Reports -> Update Status

**8. Configure WSUS to Use SSL**

* Configure SSL on WSUS Server -> Update Group Policy to use "https://\[WSUS\_SERVER]"

**9. Run WSUS Cleanup**

```
Get-WsusServer | Invoke-WsusServerCleanup -CleanupObsoleteComputers -CleanupObsoleteUpdates -CleanupUnneededContentFiles -CompressUpdates -DeclineExpiredUpdates -DeclineSupersededUpdates
```

**10. Set WSUS to Download from Microsoft Update**

Navigate through WSUS Console -> Options -> Update Source and Proxy Server -> Synchronize from Microsoft Update

**11. Configure Update Files and Languages**

Navigate through WSUS Console -> Options -> Update Files and Languages -> Store update files locally on this server

**12. Configure Automatic Approvals**

Navigate through WSUS Console -> Options -> Automatic Approvals -> Add Rule

**13. Retrieve WSUS Synchronization Status**

```
PowerShellCopy codeGet-WsusServer | Get-WsusSubscription | Get-WsusSynchronizationStatus
```

**14. Configure WSUS Email Notifications**

Navigate through WSUS Console -> Options -> Email Notifications -> Configure SMTP Server and Notification Options

**15. Manually Add a Computer to WSUS**

```
PowerShellCopy codeAdd-WsusComputer -ComputerToAdd "ComputerName" -TargetGroupName "SecureGroup"
```

**16. Retrieve WSUS Update Installations**

Navigate through WSUS Console -> Reports -> Update Installations

**17. Configure WSUS Reporting Rollup**

Navigate through WSUS Console -> Options -> Reporting Rollup -> Enable roll up of update status from replica downstream servers

**18. Set WSUS Clients to Download from Peers**

* Configure Delivery Optimization on Clients via GPO -> Set Download Mode to "LAN" (Value: 1)

**19. Retrieve WSUS Computer Status**

Navigate through WSUS Console -> Computers -> Select a Computer Group -> Status

**20. Configure WSUS Products and Classifications**

Navigate through WSUS Console -> Options -> Products and Classifications -> Select Products to Update
