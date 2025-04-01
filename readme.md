## Windows Event Code 39 and ADCS Exploitation: Privilege Escalation in Windows Environments

### Introduction

Privilege escalation is a critical post-exploitation goal for attackers within Windows environments. One emerging vector is Active Directory Certificate Services (ADCS), which has been revealed as a powerful yet often misconfigured attack surface. ADCS issues digital certificates used for secure communications and identity verification. If misconfigured, it allows attackers to impersonate users, escalate privileges, and persist within a network—all without using passwords.

Windows Event Code 39 (Event ID 39) is a security-relevant signal tied to certificate-based authentication anomalies, particularly after Microsoft’s 2022 changes to enforce strong certificate mappings. This paper focuses on how attackers exploit ADCS misconfigurations—specifically ESC1 to ESC8 techniques—to elevate privileges, how Event Code 39 fits into detection strategies, and actionable prevention, detection, and hardening strategies.

---

### Understanding Windows Event Code 39

**Event ID 39** is logged by the Key Distribution Center (KDC) when a certificate is presented during Kerberos authentication but fails strong mapping requirements. 

#### Example Log Pattern (KDC - Event 39):
```
Log Name:      System
Source:        Microsoft-Windows-Kerberos-Key-Distribution-Center
Event ID:      39
Level:         Warning
Description:   The Key Distribution Center denied a certificate logon request... Certificate mapping failed.
```

**Why it matters**:
- Indicates attempted certificate-based authentication with improper or spoofed certificate.
- Key detection point for ADCS abuse, especially post KB5014754 enforcement.

#### Detection Tools:
- **Windows Event Viewer / Sysmon**
- **SIEM solutions** (e.g., Splunk, Sentinel) with Event ID 39 correlation
- **Microsoft Defender for Identity** with ADCS sensor

---

### How Attackers Exploit ADCS (ESC1–ESC8)

#### What attackers look for:
- Templates with "Enrollee Supplies Subject"
- Templates with "Any Purpose" EKU or "Client Authentication"
- CA with `EDITF_ATTRIBUTESUBJECTALTNAME2` flag enabled
- Users/groups with ManageCA or ManageTemplates rights
- Web Enrollment service enabled (ESC8)

#### Common Tools:
- **Certify** (https://github.com/GhostPack/Certify)
- **Certipy** (https://github.com/ly4k/Certipy)
- **Mimikatz** (for TGT/PKINIT abuse)
- **Impacket (ntlmrelayx)** – for NTLM relay to ADCS (ESC8)

#### MITRE ATT&CK Mapping:
- **T1550.003** – Use Alternate Authentication Material: Web Tokens
- **T1550.004** – Smart Card Authentication Abuse
- **T1557.001** – Adversary-in-the-Middle: LLMNR/NBT-NS Poisoning and SMB Relay
- **T1003.006** – Credential Dumping: DCSync

#### Exploitation Scenarios:

**Scenario 1: ESC1 (Enrollee Supplies Subject)**
```
Command:
certify.exe request /ca:corp-CA\corp-DC /template:User /altname:administrator@corp.local
```
**Result:** Low-priv user receives cert for Domain Admin. Can request TGT via PKINIT.

**Scenario 2: ESC6 + ESC1 via CA Flag**
```
reg query HKLM\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\<CAName> /v EditFlags
```
**If flag `EDITF_ATTRIBUTESUBJECTALTNAME2` is set,** attacker can supply SAN even if template disallows it.

**Scenario 3: ESC8 (NTLM Relay via PetitPotam)**
```
ntlmrelayx.py -t http://CA/certsrv/certfnsh.asp -smb2support --adcs
```
**Result:** Relay DC's NTLM auth to ADCS. Attacker gets cert for DC, escalates to Domain Admin.

---

### Prevention and Hardening

#### 1. **Patch and Configure Strong Certificate Mapping**
- Deploy KB5014754 to all DCs.
- Set registry:
```
reg add HKLM\SYSTEM\CurrentControlSet\Services\Kdc /v StrongCertificateBindingEnforcement /t REG_DWORD /d 2 /f
```
- Validate with Event ID 39 logs.

#### 2. **Restrict Certificate Templates**
- Disable "Enrollee Supplies Subject" unless absolutely needed.
- Set EKUs to specific purposes (remove "Any Purpose").
- Require approval or authorized signatures for sensitive templates.

#### 3. **Secure CA Configuration**
- Remove web enrollment if not required.
- Enforce HTTPS with Extended Protection for Authentication (EPA).
- Disable NTLM if feasible.

#### 4. **Audit and Monitor**
- Use Certify or Certipy to simulate audits:
```
certipy find -u user -p pass -target domain.local
```
- Audit CA and template ACLs for unexpected write or enroll permissions.

#### 5. **Deploy MDI ADCS Sensor**
- Gain visibility into abnormal certificate issuance.
- Detect certificate-based lateral movement and forgery.

---

### Conclusion

ADCS exploitation presents a stealthy and dangerous privilege escalation path in Windows domains. Event ID 39 serves as a key early-warning indicator of abnormal or failed certificate-based authentications, especially after Microsoft’s enforcement of strong mappings. With real-world abuse of ADCS (e.g., CVE-2022-26923, PetitPotam), organizations must proactively audit their PKI infrastructure, limit enroll rights, apply patches, and monitor certificate usage.

With careful implementation of tooling like Certipy and Defender for Identity, security teams can detect, prevent, and harden against certificate abuse vectors before attackers escalate privileges and achieve persistence.

---

### References
- SpecterOps: https://posts.specterops.io/certified-pre-owned-d95910965cd2
- Microsoft KB5014754: https://support.microsoft.com/help/5014754
- Certipy: https://github.com/ly4k/Certipy
- Certify: https://github.com/GhostPack/Certify
- MDI ADCS Sensor: https://techcommunity.microsoft.com/t5/security-compliance-and-identity/microsoft-defender-for-identity-adds-ad-cs-sensor-preview/ba-p/3850142
- MITRE ATT&CK: https://attack.mitre.org
- PetitPotam Attack: https://github.com/topotam/PetitPotam
