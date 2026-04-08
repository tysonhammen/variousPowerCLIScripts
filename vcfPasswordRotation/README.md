# Password rotation scripts

## `VCF-RotatePasswords.ps1` (VMware Cloud Foundation)

Uses **PowerVCF** against **SDDC Manager** to **rotate** credentials it already manages (`ESXI`, `VCENTER`, `PSC`, `NSXT_MANAGER`, etc.), then exports generated passwords to CSV. Does **not** apply to standalone VxRail clusters with no SDDC Manager.

**Requirements:** `VMware.PowerCLI`, `PowerVCF`, SDDC `admin@local` (or equivalent).

---

## `VxRail-RotateIntegrationPasswords.ps1` (standalone VxRail, vSphere 8.x)

End-to-end rotation for **VxRail integration** accounts that are **not** in SDDC Manager, aligned with [Dell KB 000157662](https://www.dell.com/support/kbdoc/en-us/000157662/dell-emc-vxrail-how-to-get-or-update-management-account-in-vxrail-7-0-010-or-higher) (VxRail 7.0.010+ / 8.x).

### Plan (incorporated into the script flow)

1. **vCenter `vsphere.local` user (VxRail management account)**  
   - **Lockbox:** SSH to VxRail Manager → `sudo systemctl stop vmware-marvin` → `PUT` `management_account_vc` (password is **base64** in JSON, as in the KB).  
   - **SSO:** Reset the same plaintext password on the person user via **`VMware.vSphere.SsoAdmin`** (`Connect-SsoAdminServer`, `Get-SsoPersonUser`, `Set-SsoPersonUser -NewPassword`), wrapping the [vSphere SSO Admin API](https://github.com/vmware-archive/PowerCLI-Example-Scripts/tree/master/Modules/VMware.vSphere.SsoAdmin) (gallery: `Install-Module VMware.vSphere.SsoAdmin`).  
   - **Lockbox:** `sudo systemctl start vmware-marvin`.

2. **ESXi management user (per host)**  
   For each host: stop Marvin → `PUT` `management_account_esxi__<PowerEdgeServiceTag>` → set password on the host with **PowerCLI `Get-EsxCli` / `system account set`** → start Marvin.

3. **Afterward (manual if required)**  
   Dell KB may require re-enabling health monitoring and restarting `vmware-marvin`; comments in the script point to the same `curl`/`systemctl` steps—run on VxRail Manager if your runbook requires them. Run **VxVerify** and confirm VxRail / vCenter health.

### Requirements

| Dependency | Purpose |
|------------|---------|
| **OpenSSH client** (`ssh` in PATH) | Remote commands on VxRail Manager |
| **VMware.PowerCLI** | `Connect-VIServer`, `Get-VMHost`, `Get-EsxCli` |
| **VMware.vSphere.SsoAdmin** | `Connect-SsoAdminServer`, `Set-SsoPersonUser` for `vsphere.local` |
| **SSH user** (default `mystic`) | Must be able to **`sudo`** `systemctl` and **`curl`** to the lockbox socket **non-interactively** (typically passwordless sudo for those commands) |

### Example (prompt for one new password; rotate VC + ESXi)

```powershell
.\VxRail-RotateIntegrationPasswords.ps1 `
  -VxRailManagerFQDN 'vxrail-mgr.lab.example.com' `
  -vCenterServer 'vcenter.lab.example.com' `
  -SsoAdminCredential (Get-Credential -Message 'SSO admin (e.g. administrator@vsphere.local)') `
  -SkipViCertificateCheck -SkipSsoCertificateCheck `
  -RotateVc `
  -VxRailVcPersonUserName 'svc-vxrail' `
  -VxRailVcPersonDomain 'vsphere.local' `
  -RotateEsxi `
  -EsxiMgmtUsername 'esxmgmt' `
  -EsxiHosts @(
    @{ HostFQDN = 'esxi01.lab.example.com'; ServiceTag = 'AB1CDE2' },
    @{ HostFQDN = 'esxi02.lab.example.com'; ServiceTag = 'XY9ZZZ1' }
  ) `
  -PasswordMode Prompt `
  -ExportPlaintextCsv
```

Optional: `-SshIdentityFile 'C:\Users\me\.ssh\id_rsa'`, `-ViCredential` if different from SSO admin for `Connect-VIServer`.

Use **`-WhatIf`** to see which operations would run. **`-ExportPlaintextCsv`** writes the new password to disk—restrict ACLs or remove after archival.

### Caveats

- Confirm **service tags** and **SSO user name** with lockbox **GET** from the KB before first use.  
- **Usernames** passed into the remote JSON must be safe for the transport (script validates: alphanumeric, `@`, `.`, `_`, `-`).  
- **Support:** `VMware.vSphere.SsoAdmin` is community/example lineage (archived GitHub repo); validate in a lab on your vSphere 8 build.
