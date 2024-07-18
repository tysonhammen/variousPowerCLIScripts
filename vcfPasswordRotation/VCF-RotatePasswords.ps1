Import-Module vmware.powercli
Import-Module powervcf

#General Variables
$sddcManager = "vcf-m01-sddcm01.lab.influencedigital.com"
$adminUser = 'admin@local'
$adminUserPWSecure = Read-Host -Prompt 'Enter password' -AsSecureString
$BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($adminUserPWSecure)
$adminUserPW = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
[Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR)
$userPath = "C:\users\tyson\Documents"

#Request a token from SDDC Manager
Request-VCFToken -fqdn $sddcManager -username $adminUser -password $adminUserPW

#Enter the products to rotate passwords for
$productsToRotate = "ESXI","VCENTER","PSC","NSXT_MANAGER"

$newPasswords = @()

function Generate-credentialObject {
    param (
        [string]$operationType,
        [string]$resourceName,
        [string]$resourceType,
        [string]$credentialType,
        [string]$username
    )

    $jsonObject = @{
        operationType = $operationType
        elements      = @(
            @{
                resourceName = $resourceName
                resourceType = $resourceType
                credentials  = @(
                    @{
                        credentialType = $credentialType
                        username       = $username
                    }
                )
            }
        )
    }

    return $jsonObject | ConvertTo-Json -Depth 4
}

foreach ( $product in $productsToRotate ) {

    $items = Get-VCFCredential -resourceType $product

    foreach ( $item in $items )
    {
        
        $credJSON = Generate-credentialObject -operationType ROTATE -resourceName $item.resource.resourceName -resourceType $item.resource.resourceType -credentialType $item.credentialType -username $item.username
        $credRotateJob = Set-VCFCredential -json $credJSON
        sleep 10
        $credRotateJob.id

        $taskStatus = "NOT_STARTED"
        While ($taskStatus -ne "SUCCESSFUL") {
            $currentStatus = Get-VCFTask -id $credRotateJob.id
            $taskStatus = $currentStatus.status
            if ($taskStatus -eq "IN_PROGRESS") {
                Write-Host "Task in progress for host:"$item.resource.resourceName" username:"$item.username", task id:"$credRotateJob.id
                }
            elseif ($taskStatus -eq "SUCCESSFUL") {
                sleep 10
                $newCreds = Get-VCFCredential -resourceName $item.resource.resourceName -id $item.id|where-Object {$_.username -eq $item.username}
                Write-Host "Task Successful for host:"$item.resource.resourceName "username:" $newCreds.username" new password is" $newCreds.password
                $newPasswords += [pscustomobject]@{
                    Hostname    = $item.resource.resourceName
                    Username    = $newCreds.username
                    NewPassword = $newCreds.password
                    }
                }
            sleep 10
        }
    }
}

# Export the results to a CSV file
$dateString = (Get-Date).ToString("yyyyMMdd")
$csvFileName = "vcfPasswords_$dateString.csv"
$csvPath = Join-Path -Path $userPath -ChildPath $csvFileName
$newPasswords | Export-Csv -Path $csvPath -NoTypeInformation