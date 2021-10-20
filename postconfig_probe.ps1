<#
.SYNOPSIS
This scripts start CheckMK probe servers and add it to his correspondig hostgroup in Foreman to inherit the right puppet classes.
.DESCRIPTION
This scripts start CheckMK probe servers and add it to his correspondig hostgroup in Foreman to inherit the right puppet classes.

You must provide the CSV file result used in the previous "deploy_probe.ps1" script.

Ensure that Network have created the antispoofing firewall rules to have correct connectivity.

name,ipadd4,ipadd6,cluster,portgroup,privnet,mac,dhcpfqdn

name: name of the vm ( ex: es-lgr-lpngp1zz01-01)
ipadd4: IPv4 of the VM for the public interface
ipadd6: IPv6 of the VM for the public interface
cluster: Datastore cluster location
portgroup: vlan of the pulic interface
privnet: vlan for the private network interface
mac: this parameter will be automatically feeded during the script just after the VM creation
dhcpfqdn: specifiy the fqdn that will relies on the public IP so during the script, the DHCP reervation will be automatically created.

.PARAMETER probeFile
Mandatory
You must specify the path to your CSV file, see description for more details about it.
Default value: -
.EXAMPLE
.\deploy_probe.ps1 -probeFile pathtoyourcsvresuldtdeployfile
Execute the script with the path to your CSV result of the deployment script.
.LINK 
Online version: https://confluence.united-internet.org/display/~jlobatoalonso/deploy+probe+script
.NOTES
2021 Javier Lobato 
2021/10/15 First Release
#>

Param(
    [Parameter(Mandatory = $True)] [string]$probeFile = ""
    )

if (!$probeFile)
    {
    Write-Host "Please, give the path to the CSV resulted of the deploy process!" -ForegroundColor Red
	exit 10
    }

if (-not (Get-PSSnapin VMware.VimAutomation.Core -ErrorAction SilentlyContinue)) {
    Add-PSSnapin VMware.VimAutomation.Core -ErrorAction SilentlyContinue
    if (-not (Get-PSSnapin VMware.VimAutomation.Core -ErrorAction SilentlyContinue)) {
        # If PowerCLI 5.8 snapins are not loaded, try importing the new PowerCLI 6.5 modules
        Get-Module -ListAvailable VM* | Import-Module
        if ((Get-Module -Name "VM*") -eq $null)
        {
            # If neither PowerCLI 5.8 nor PowerCLI 6.5 are installed, exit with error
            Write-Host "WARNING: You must have POWERCLI installed on your system" -BackgroundColor Red
            Write-Host "Download here: https://www.vmware.com/support/developer/PowerCLI/"
            Start-Sleep "https://www.vmware.com/support/developer/PowerCLI/"
            exit 
        }
    }
}

#check for previous vcenter connections
if (($DefaultVIServers).Count -ne 0){
	write-host "There are a previous vCenter active connection!!! Exit!!! " -ForegroundColor Red
	exit (1)
}

# Load PowerCLI module
Get-Module -ListAvailable VM* | Import-Module

# Get info from CSV
try {
    $probeList = Import-Csv -Path $probeFile
} catch {
    Write-Error -ForegroundColor:Red "Probe file not found. Exiting!"
    exit
}

#Ask for credentials and connect to vCenter
$myCredentials = Get-Credential -Message "Type user credentials for the vCenter connection"

foreach ($probe in $probeList)
{
    # Calculate variables
    $probe.name -match "^([a-z]{2})-[a-z]{3}-[a-z]{2}ng(p?)([d0-9])zz([0-9]{2,3})-([0-2]{2})$" | Out-Null
    $dcPrefix = $Matches[1]
    $isPre = $Matches[2]
    $siteDigit = $Matches[3]
    $probeType = $Matches[5]

        if ($siteDigit -eq "d") { $siteNumber = "9" }
        else { $siteNumber = $siteDigit }
        switch ($dcPrefix) {
            "es" {

                if ($isPre -eq "p")
                {
                    if ($siteDigit -eq "2")
                    {
                        $dc = "pru"
                    }
                    else
                    {
                        $dc = "pre"
                    }
                }
                else
                {
                    $dc = "por"                    
                }
            }
            "us" {
                $dc = "lxa"
            }
            "de" {
                $dc = "rhr"
            }
            "gb" {
                $dc = "glo"
            }
            default {
                Write-Error "Invalid datacenter! Please check provided parameter and re-run with a valid one!"
                exit
            }
        }
    $site = $dc + $siteDigit

    # Get vCenter and power on VM

    $destVcenter = $probe.cluster.Split("-")[0] + "-" + $probe.cluster.Split("-")[1] + ".por-ngcs.lan"
    Write-Host "Connecting to $($vcenter) to power on $($probe.name)!"
    $vcenter = Connect-VIServer -Server $destVcenter -Credential $myCredentials -WarningAction:SilentlyContinue        
    Start-VM -Server $vcenter -VM $probe.name
               
    Disconnect-VIServer -Server $destVcenter -Confirm:$false
    
}

# Add each host to his Foreman HostGroup depending from his site

foreach ($probe in $probeList)
{
    # Variblables for Foreman depending from NGCS site
<#
    switch ( $site )
    {
        "pre2" { $idhostgroup = 134 }
        "glo1" { $idhostgroup = 139 }
        "glo2" { $idhostgroup = 140 }
        "lxa1" { $idhostgroup = 138 }
        "lxa2" { $idhostgroup = 137 }
        "lxa3" { $idhostgroup = 136 }
        "por1" { $idhostgroup = 141 }
        "por2" { $idhostgroup = 142 }
        "rhr1" { $idhostgroup = 143 }
        "rhr2" { $idhostgroup = 144 }
        "rhr3" { $idhostgroup = 145 }
        "rhr4" { $idhostgroup = 146 }
    }
#>
    # Variables for Foreman REST API
        
    $username_ngcs = Read-Host "Enter your NGCS username: "
    $password_ngcs = Read-Host "Enter your NGCS password: " -AsSecureString
    $password_ngcs = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($password_ngcs))
    $ngcs_creds = $username_ngcs + ":" + $password_ngcs
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($ngcs_creds)
    $encodedlogin=[Convert]::ToBase64String($bytes)
    $authheader = "Basic " + $encodedlogin
    
     # Searching for HostGroupID over Foreman REST API

    $params_search_hostgroup = @{
    Uri         = "https://por-puppet2.por-ngcs.lan/api/hostgroups`?search=name=`"ngcs_probe`""
    Headers     = @{ 'Authorization' = $($authheader) }
    Method      = 'GET'
    ContentType = 'application/json'
                                }

    $response_api_hostgroups = Invoke-RestMethod @params_search_hostgroup 

    $idhostgroup = ($response_api_hostgroups | select-object -property id,title | where-object {$_.title -like "*$($site)*"} ).id

    # Searching for HostID over Foreman REST API

    $params_idhost = @{
        Uri         = "https://por-puppet2.por-ngcs.lan/api/hosts`?search=name=`"$($probe.name).por-ngcs.lan`""
        Headers     = @{ 'Authorization' = $($authheader) }
        Method      = 'GET'
        ContentType = 'application/json'
    }

    $response_api_idhost = Invoke-RestMethod @params_idhost

    $idhost = $response_api_idhost.results.id


     # Update HostGroup ID for host over Foreman REST API
    $Body_HostGroup = 
'{
  "host": {
        "hostgroup_id": $idhostgroup
         }
}'
    
    #$jsonpayload_hostgroup = ($Body_HostGroup | ConvertTo-Json)

    $params_hostgroup = @{
        Uri         = "https://por-puppet2.por-ngcs.lan/api/hosts/$($idhost)"
        Headers     = @{ 'Authorization' = $($authheader) }
        Method      = 'PUT'
        Body        = $Body_HostGroup 
        ContentType = 'application/json'
    }
    
    $response_api_hostgroup = Invoke-RestMethod @params_hostgroup
#>
    if ($response_api_hostgroup.hostgroup_id -eq $idhostgroup)
    {
        Write-Host "Add $($probe.name) to Foreman Hostgroup $($idhostgroup) for Site $($site)"    
    }
    else {
        Write-Host "Error contacting with Foreman API"
    }
    
}


# SSH credential for default secret

$securepassword = Read-host -Prompt "Please, introduce the default password for root user in NGCS" -AsSecureString
$sshpass = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($securepassword))

function plink_exec {

    foreach ($probe in $probelist)
    {
        plink -batch -pw $sshpass $root@$($probe.name) "puppet agent -t"
        Write-Host "Correctly refresh Puppet agent in $($probe.name)" -ForegroundColor Green

    }      
}

plink_exec

Write-Host "Successfully postconfigured all VM's from $($probeFile)"