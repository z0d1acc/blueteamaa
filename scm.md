# SCM

#### **Overview** <a href="#overview" id="overview"></a>

Microsoft's Security Compliance Manager (SCM) is a robust tool designed to help organizations manage and create security baselines for various Microsoft products. It provides ready-to-deploy policies and Desired Configuration Management (DCM) packs that are tested and fully supported.

**Key Features of SCM**

* **Security Baselines**: Pre-configured security settings for various Microsoft products.
* **Configuration Management**: Manage and customize security baselines.
* **Export Capabilities**: Export security baselines in various formats (GPO backup, SCAP, DCM, etc.)
* **Security Guidance**: Access to security best practices and guidance.

#### **Cheat Sheet** <a href="#cheat-sheet" id="cheat-sheet"></a>

1. **Install SCM**: Ensure that you have the latest version of SCM installed.
2. **Download Baselines**: Download the latest security baselines for the Microsoft products in use.
3. **Import Baselines**: Import security baselines into SCM.
4. **Customize Baselines**: Adjust the settings in the security baselines to meet the specific needs of your organization.
5. **Export Baselines**: Export the customized baselines in the desired format (e.g., GPO backup, Excel, etc.)
6. **Deploy Baselines**: Implement the baselines in your environment using Group Policy or SCCM.
7. **Monitor Compliance**: Regularly check systems for compliance with the applied baselines.
8. **Update Baselines**: Periodically check for and apply updates to security baselines.
9. **Audit and Review**: Conduct audits and review security baselines to ensure they align with organizational security needs.
10. **Document Changes**: Keep a log of all changes made to security baselines and configurations.

#### Examples for Hardening with SCM <a href="#examples-for-hardening-with-scm" id="examples-for-hardening-with-scm"></a>

**1. Import Windows 10 Baseline**

* SCM Home -> Import Baseline -> Windows 10

**2. Customize Windows Server 2019 Baseline**

* SCM Home -> Windows Server 2019 Baseline -> Customize

**3. Export Office 365 ProPlus Baseline as GPO**

* Customized Office 365 ProPlus Baseline -> Export as GPO Backup

**4. Deploy Windows 10 Baseline with Group Policy**

* Exported Windows 10 GPO Backup -> Import in Group Policy Management Console

**5. Monitor Compliance for Windows Server 2016**

* Deployed Windows Server 2016 Baseline -> Monitor using SCCM

**6. Update Windows 10 Baseline**

* SCM Home -> Windows 10 Baseline -> Check for Updates

**7. Audit SQL Server Configurations**

* Deployed SQL Server Baseline -> Audit using SCM

**8. Document Changes to Exchange Server Baseline**

* Customized Exchange Server Baseline -> Document Changes

**9. Manage Versioning for Windows 10 Baseline**

* Documented Windows 10 Baseline -> Manage Versioning

**10. Validate Compliance for Windows Server 2019**

* Deployed Windows Server 2019 Baseline -> Validate using SCM

**11. Customize and Export Edge Browser Baseline**

* SCM Home -> Edge Browser Baseline -> Customize -> Export

**12. Deploy Office 2019 Baseline with SCCM**

* Exported Office 2019 Baseline -> Deploy using SCCM

**13. Review and Update Domain Controller Baseline**

* SCM Home -> Domain Controller Baseline -> Review and Update

**14. Monitor Compliance for Office 2016 Baseline**

* Deployed Office 2016 Baseline -> Monitor using SCM

**15. Export and Deploy Windows Defender Baseline**

* Customized Windows Defender Baseline -> Export -> Deploy using Group Policy

**16. Validate Compliance for SharePoint Server Baseline**

* Deployed SharePoint Server Baseline -> Validate using SCM

**17. Review and Customize Windows Firewall Baseline**

* SCM Home -> Windows Firewall Baseline -> Customize

**18. Export and Document Windows 8.1 Baseline**

* Customized Windows 8.1 Baseline -> Export -> Document Changes

**19. Deploy and Monitor SQL Server Baseline**

* Exported SQL Server Baseline -> Deploy using SCCM -> Monitor Compliance

**20. Audit and Update Windows Server 2012 R2 Baseline**

* Deployed Windows Server 2012 R2 Baseline -> Audit using SCM -> Update Baseline
