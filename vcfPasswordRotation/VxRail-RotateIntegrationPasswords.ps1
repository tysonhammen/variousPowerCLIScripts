#Requires -Version 5.1
<#
.SYNOPSIS
    Rotates VxRail integration passwords: vSphere.local user (SSO Admin API), ESXi management users, and VxRail Manager lockbox.

.DESCRIPTION
    Standalone VxRail (not SDDC Manager). Order follows Dell KB 000157662 for lockbox updates:
      vCenter track: stop vmware-marvin -> PUT management_account_vc -> reset SSO password -> start vmware-marvin
      ESXi track (per host): stop vmware-marvin -> PUT management_account_esxi__<ServiceTag> -> esxcli account set -> start vmware-marvin

    SSO password reset uses VMware.vSphere.SsoAdmin (PowerShell Gallery: Install-Module VMware.vSphere.SsoAdmin).
    References:
      https://www.dell.com/support/kbdoc/en-us/000157662/dell-emc-vxrail-how-to-get-or-update-management-account-in-vxrail-7-0-010-or-higher
      https://github.com/vmware-archive/PowerCLI-Example-Scripts/tree/master/Modules/VMware.vSphere.SsoAdmin

.NOTES
    SSH user (default mystic) must be able to run: sudo systemctl, sudo curl to the lockbox socket (passwordless sudo or interactive is not supported here).
    OpenSSH client (ssh) must be in PATH. Test with -WhatIf before production.
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Mandatory = $true)]
    [string] $VxRailManagerFQDN,

    [Parameter(Mandatory = $false)]
    [string] $VxRailSshUser = 'mystic',

    [Parameter(Mandatory = $false)]
    [int] $VxRailSshPort = 22,

    [Parameter(Mandatory = $false)]
    [string] $SshIdentityFile,

    [Parameter(Mandatory = $true)]
    [string] $vCenterServer,

    [Parameter(Mandatory = $true)]
    [pscredential] $SsoAdminCredential,

    [Parameter(Mandatory = $false)]
    [pscredential] $ViCredential,

    [Parameter(Mandatory = $false)]
    [switch] $RotateVc,

    [Parameter(Mandatory = $false)]
    [string] $VxRailVcPersonUserName,

    [Parameter(Mandatory = $false)]
    [string] $VxRailVcPersonDomain = 'vsphere.local',

    [Parameter(Mandatory = $false)]
    [switch] $RotateEsxi,

    [Parameter(Mandatory = $false)]
    [string] $EsxiMgmtUsername,

    [Parameter(Mandatory = $false)]
    [System.Collections.Hashtable[]] $EsxiHosts,

    [Parameter(Mandatory = $false)]
    [ValidateSet('Generate', 'Prompt', 'SecureString')]
    [string] $PasswordMode = 'Prompt',

    [Parameter(Mandatory = $false)]
    [securestring] $NewPassword,

    [Parameter(Mandatory = $false)]
    [switch] $SkipViCertificateCheck,

    [Parameter(Mandatory = $false)]
    [switch] $SkipSsoCertificateCheck,

    [Parameter(Mandatory = $false)]
    [string] $OutputDirectory = (Join-Path $env:USERPROFILE 'Documents'),

    [Parameter(Mandatory = $false)]
    [switch] $ExportPlaintextCsv
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function ConvertFrom-SecureStringPlain {
    param([securestring] $SecureString)
    $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecureString)
    try {
        return [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)
    }
    finally {
        [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) | Out-Null
    }
}

function New-RotationPassword {
    param([int] $Length = 16)
    $lower = 'abcdefghjkmnpqrstuvwxyz'
    $upper = 'ABCDEFGHJKMNPQRSTUVWXYZ'
    $digit = '23456789'
    $special = '!@#$^*'
    $all = $lower + $upper + $digit + $special
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    $bytes = New-Object byte[] ($Length)
    $rng.GetBytes($bytes)
    $chars = [char[]]::new($Length)
    $chars[0] = $lower[$bytes[0] % $lower.Length]
    $chars[1] = $upper[$bytes[1] % $upper.Length]
    $chars[2] = $digit[$bytes[2] % $digit.Length]
    $chars[3] = $special[$bytes[3] % $special.Length]
    for ($i = 4; $i -lt $Length; $i++) {
        $chars[$i] = $all[$bytes[$i] % $all.Length]
    }
    for ($i = $chars.Length - 1; $i -gt 0; $i--) {
        $j = Get-Random -Minimum 0 -Maximum ($i + 1)
        $tmp = $chars[$i]; $chars[$i] = $chars[$j]; $chars[$j] = $tmp
    }
    return -join $chars
}

function Test-LockboxUsernameSafe {
    param([string] $Name)
    if ($Name -notmatch '^[a-zA-Z0-9@._-]+$') {
        throw "Username contains characters unsafe for remote shell JSON: use only alphanumeric, @, ., _, -"
    }
}

function Invoke-VxRailLockboxPut {
    param(
        [string] $VxRailManagerFQDN,
        [string] $VxRailSshUser,
        [int] $VxRailSshPort,
        [string] $SshIdentityFile,
        [string] $CredentialName,
        [string] $LockboxUsername,
        [string] $PlainPassword
    )

    Test-LockboxUsernameSafe -Name $LockboxUsername

    $pwBytes = [System.Text.Encoding]::UTF8.GetBytes($PlainPassword)
    $encoded = [Convert]::ToBase64String($pwBytes)

    $credObj = [ordered]@{
        credential_name = $CredentialName
        username        = $LockboxUsername
        password        = $encoded
    }
    $body = @{
        lockbox_name = 'SYSTEM'
        credentials  = @($credObj)
    } | ConvertTo-Json -Compress -Depth 5

    # Avoid shell-quoting issues (e.g. passwords with quotes): send JSON as base64 to the remote shell.
    $jsonB64 = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($body))
    $bash = @"
set -e
sudo systemctl stop vmware-marvin
echo '$jsonB64' | base64 -d | curl -sS -X PUT --unix-socket /var/lib/vxrail/nginx/socket/nginx.sock \
  -H 'accept: application/json' -H 'Content-Type: application/json' \
  -d @- \
  'http://localhost/rest/vxm/internal/lockbox/v1/credentials'
sudo systemctl start vmware-marvin
"@

    $sshTarget = "${VxRailSshUser}@${VxRailManagerFQDN}"
    $sshArgs = @('-p', "$VxRailSshPort")
    if ($SshIdentityFile) {
        $sshArgs += '-i', $SshIdentityFile
    }
    $sshArgs += $sshTarget, $bash

    Write-Verbose "SSH: ssh $($sshArgs -join ' ')"
    & ssh @sshArgs
    if ($LASTEXITCODE -ne 0) {
        throw "SSH remote lockbox update failed with exit code $LASTEXITCODE"
    }
}

function Set-EsxiManagementUserPasswordViaEsxCli {
    param(
        [Parameter(Mandatory = $true)]
        $VMHost,

        [Parameter(Mandatory = $true)]
        [string] $AccountId,

        [Parameter(Mandatory = $true)]
        [string] $PlainPassword
    )

    $esxCli = Get-EsxCli -VMHost $VMHost -V2
    $esxCli.system.account.set.Invoke(@{
            id       = $AccountId
            password = $PlainPassword
        })
}

#region Prerequisites
if (-not (Get-Command ssh -ErrorAction SilentlyContinue)) {
    throw 'OpenSSH client (ssh) not found in PATH. Install OpenSSH Client or add ssh.exe to PATH.'
}

Import-Module VMware.PowerCLI -ErrorAction Stop
if ($RotateVc) {
    Import-Module VMware.vSphere.SsoAdmin -ErrorAction Stop
}

if (-not $RotateVc -and -not $RotateEsxi) {
    throw 'Specify at least one of -RotateVc or -RotateEsxi.'
}

if ($RotateVc -and [string]::IsNullOrWhiteSpace($VxRailVcPersonUserName)) {
    throw '-RotateVc requires -VxRailVcPersonUserName (SSO person user name without domain, e.g. svc-vxrail).'
}

if ($RotateEsxi) {
    if ([string]::IsNullOrWhiteSpace($EsxiMgmtUsername)) {
        throw '-RotateEsxi requires -EsxiMgmtUsername.'
    }
    Test-LockboxUsernameSafe -Name $EsxiMgmtUsername
    if (-not $EsxiHosts -or $EsxiHosts.Count -lt 1) {
        throw '-RotateEsxi requires -EsxiHosts with at least one entry @{ HostFQDN = ''...''; ServiceTag = ''...'' }.'
    }
}

$viCred = if ($ViCredential) { $ViCredential } else { $SsoAdminCredential }

if ($SkipViCertificateCheck) {
    Set-PowerCLIConfiguration -InvalidCertificateAction Ignore -Confirm:$false -Scope Session | Out-Null
}

#endregion

#region New password
$plainNew = $null
switch ($PasswordMode) {
    'Generate' { $plainNew = New-RotationPassword }
    'Prompt' {
        $sec = Read-Host -AsSecureString -Prompt 'Enter new password for rotation'
        $plainNew = ConvertFrom-SecureStringPlain -SecureString $sec
    }
    'SecureString' {
        if (-not $NewPassword) { throw '-PasswordMode SecureString requires -NewPassword.' }
        $plainNew = ConvertFrom-SecureStringPlain -SecureString $NewPassword
    }
}
#endregion

$log = [System.Collections.Generic.List[object]]::new()
$ssoConn = $null
$viServer = $null

try {
    if ($RotateVc) {
        if ($PSCmdlet.ShouldProcess($VxRailManagerFQDN, 'PUT management_account_vc + reset vsphere.local password')) {
            $lockboxUser = "$VxRailVcPersonUserName@$VxRailVcPersonDomain"
            Invoke-VxRailLockboxPut -VxRailManagerFQDN $VxRailManagerFQDN -VxRailSshUser $VxRailSshUser `
                -VxRailSshPort $VxRailSshPort -SshIdentityFile $SshIdentityFile `
                -CredentialName 'management_account_vc' -LockboxUsername $lockboxUser -PlainPassword $plainNew

            $ssoConnectParams = @{
                Server     = $vCenterServer
                Credential = $SsoAdminCredential
            }
            if ($SkipSsoCertificateCheck) {
                $ssoConnectParams['SkipCertificateCheck'] = $true
            }
            $ssoConn = Connect-SsoAdminServer @ssoConnectParams
            $person = Get-SsoPersonUser -Server $ssoConn -Name $VxRailVcPersonUserName -Domain $VxRailVcPersonDomain
            if (-not $person) {
                throw "SSO person user not found: $VxRailVcPersonUserName in domain $VxRailVcPersonDomain"
            }
            Set-SsoPersonUser -Server $ssoConn -User $person -NewPassword $plainNew | Out-Null
            $log.Add([pscustomobject]@{
                    Component = 'vCenterLockbox+SSO'
                    Target    = $lockboxUser
                    Status    = 'Updated'
                })
        }
    }

    if ($RotateEsxi) {
        $viServer = Connect-VIServer -Server $vCenterServer -Credential $viCred

        foreach ($row in $EsxiHosts) {
            $hostFqdn = $row.HostFQDN
            $st = $row.ServiceTag
            if ([string]::IsNullOrWhiteSpace($hostFqdn) -or [string]::IsNullOrWhiteSpace($st)) {
                throw 'Each EsxiHosts entry must include HostFQDN and ServiceTag.'
            }
            $credName = "management_account_esxi__$st"

            if ($PSCmdlet.ShouldProcess($hostFqdn, "PUT $credName + ESXi account password")) {
                Invoke-VxRailLockboxPut -VxRailManagerFQDN $VxRailManagerFQDN -VxRailSshUser $VxRailSshUser `
                    -VxRailSshPort $VxRailSshPort -SshIdentityFile $SshIdentityFile `
                    -CredentialName $credName -LockboxUsername $EsxiMgmtUsername -PlainPassword $plainNew

                $vmh = Get-VMHost -Name $hostFqdn -ErrorAction Stop
                Set-EsxiManagementUserPasswordViaEsxCli -VMHost $vmh -AccountId $EsxiMgmtUsername -PlainPassword $plainNew

                $log.Add([pscustomobject]@{
                        Component = 'EsxiLockbox+Host'
                        Target    = $hostFqdn
                        Status    = 'Updated'
                    })
            }
        }
    }
}
finally {
    if ($ssoConn) {
        Disconnect-SsoAdminServer -Server $ssoConn -ErrorAction SilentlyContinue
    }
    if ($viServer) {
        Disconnect-VIServer -Server $viServer -Confirm:$false -ErrorAction SilentlyContinue
    }
}

#region Optional Dell KB follow-up (comment / run manually if needed)
# Health monitoring + marvin restart per KB — enable when your runbook requires it:
# curl -X PUT --unix-socket ... http://127.0.0.1/rest/vxm/internal/configservice/v1/configuration/keys/state_cluster_suppressed -d '{"value": "false"}'
# systemctl restart vmware-marvin
#endregion

$log | Format-Table -AutoSize
Write-Host 'Rotation steps completed. Run VxVerify / check VxRail health per Dell KB.'

if ($ExportPlaintextCsv) {
    $dateString = (Get-Date).ToString('yyyyMMdd_HHmmss')
    $csvPath = Join-Path $OutputDirectory "vxrail_rotation_$dateString.csv"
    $exportRows = @(
        [pscustomobject]@{ Field = 'NewPassword'; Value = $plainNew }
    ) + @($log)
    $exportRows | Export-Csv -Path $csvPath -NoTypeInformation
    Write-Warning "Plaintext password written to $csvPath - restrict ACLs or delete after archival."
}

# Clear plaintext from variable scope best-effort
$plainNew = $null
