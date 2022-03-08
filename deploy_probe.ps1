<#
.SYNOPSIS
This scripts deploy CheckMK probe servers in batch mode with DHCP reservation and DNS register creation.
.DESCRIPTION
This script deploys CheckMK probes servers for the NGCS infrastrucure, you must provide a CSV file that include these headers.
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
.\deploy_probe.ps1 -probeFile pathdeprobefile 
Execute the script with the path to your CSV file for PSS User with default DNS registry creation.
.EXAMPLE
.\deploy_probe.ps1 -probeFile pathdeprobefile  -createdns 0 -force 1
Execute the script with the path to your CSV file for PSS User and no DNS registry creation.
.LINK 
Online version: https://confluence.united-internet.org/display/~jlobatoalonso/deploy+probe+script
.NOTES
2021 Javier Lobato 
2021/09/22 First Release
2022/03/08 Change script to use VAULT for credentials and for pssuserkey and to get vcenter and datastore from CSV (if given) to do not calculate it for internal vcenters
#>

Param(
    [Parameter(Mandatory = $True)] [string]$probeFile = "",
    [Boolean]$force = $false,
    [Boolean]$createdns = $true
    )

function VAULT-GetToken {
	Param (
		[Parameter(Mandatory)][String] $uri,
		[Parameter(Mandatory)][System.Management.Automation.PSCredential]$credentials
	)
	$vaultusername=($credentials.username).Split("@")[0]
	$vaultuserpass=[Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($credentials.password))
	$jsonPayload = [PSCustomObject]@{"password"= "$vaultuserpass"} | ConvertTo-Json
	$irmParams = @{
					Uri    = "$uri/v1/auth/ldap/login/$vaultusername"
					Body   = $($jsonPayload | ConvertFrom-Json | ConvertTo-Json -Compress)
					Method = 'Post'
				}

	try{
		$result=Invoke-RestMethod @irmParams
		return $result.auth.client_token
	}catch{
		throw $_
	}
}

function VAULT-GetVault {
	Param (
		[Parameter(Mandatory)][String] $uri,
		[Parameter(Mandatory)][String] $vaulttoken
	)
	[PSCustomObject]@{'uri'= $uri + '/v1/'
                      'auth_header' = @{'X-Vault-Token'=$vaulttoken}
                      } |
    Write-Output
}

function VAULT-GetSecret {
	Param (
		[Parameter(Mandatory)][String] $uri,
		[Parameter(Mandatory)][String] $engine,
		[Parameter(Mandatory)][String] $secretpath,
		[String] $secretkey,
		[System.Management.Automation.PSCredential] $credentials,
		[String] $vaulttoken
	)
	
	if ($vaulttoken -ne ""){
		#using token to get values	
		$vaultobject = VAULT-GetVault -uri $uri -vaulttoken $vaulttoken
	}
	else{
		#negotiating token usin credentials
		$vaulttoken= VAULT-GetToken -uri $uri -credentials $credentials
		$vaultobject = VAULT-GetVault -uri $uri -vaulttoken $vaulttoken
	}
	$secreturi= $vaultobject.uri + $engine + '/data/' + $secretpath + '?/?list=true'
	try {
		$result = Invoke-RestMethod -Uri $secreturi -Headers $VaultObject.auth_header
		$data = $result | Select-Object -ExpandProperty data
		if ($secretkey -ne ""){
			#return only a desired key value
			return $data.data.$secretkey
		}
		else {
			#return all data and metadata in $secretpath
			return $data
		}
	}
	catch {
		Throw $_
	}
	
}

$vaulturi="https://itohi-vault-live.server.lan"
$vaultengine="ionos/techops/arsysproarch/secrets"
$vaultpath="ngcs/deploys"


if (!$probeFile){
    Write-Host "Please, give the path to the CSV file with all parameters as the proble_example.csv file in the DATA directory !" -ForegroundColor Red -BackgroundColor Black
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
	write-host "There are a previous vCenter active connection!!! Exit!!! " -ForegroundColor Red -BackgroundColor Black
	exit (1)
}

Write-Host "`nPreparing to connect, please introduce your NGCS credentials when prompted`n" -BackgroundColor Blue -ForegroundColor Cyan
    

# Load PowerCLI module
Get-Module -ListAvailable VM* | Import-Module

# Get info from CSV
try {
    $probeList = Import-Csv -Delimiter ',' -Path $probeFile
} catch {
    Write-Error -ForegroundColor:Red "Probe file not found. Exiting!"
    exit
}

#Ask for credentials and connect to vCenter
$myCredentials = Get-Credential -WarningAction:SilentlyContinue -Message "Please provide credentials from @ionos.com to connect to vcenter" -username "@ionos.com"

# Default variables
$DomainProvisioningUser="DomainProvisioning@por-ngcs.lan"
$DomainProvisioningPass = VAULT-GetSecret -uri $vaulturi -engine $vaultengine -secretpath $vaultpath -credentials $myCredentials -secretkey DomainProvisioning
$location = "network"
$template = "co7_64_puppet5"
$customization = "por-generic"
$numcpu = 1
$ram = 2

#create pssuser key
$pssuser_key = VAULT-GetSecret -uri $vaulturi -engine $vaultengine -secretpath $vaultpath -credentials $myCredentials -secretkey pssuser_key
[IO.File]::WriteAllLines("$($pwd.path)\tmp_key", $pssuser_key)
$ACL=Get-Acl .\tmp_key
$ACL.SetAccessRuleProtection($true,$false)
$AccessRule = New-Object System.Security.AccessControl.FileSystemAccessRule("$(whoami)","write,read,modify","Allow")
$ACL.SetAccessRule($AccessRule)
$ACL | Set-Acl -Path tmp_key

$priv_key = "$($pwd.path)\tmp_key"

foreach ($probe in $probeList)
{
    try {
        if ( $force ) {
            throw "Forced re-creation of VM and DNS entries"
        } else {
            # Will be replaced by Resolve-DnsName if powershell is upgraded in desktops
            $dnscheck = [System.Net.DNS]::GetHostAddresses("$($probe.name).por-ngcs.lan")
            Write-Host "DNS entry already exists. Please check and re-run script with -force:`$true option" -ForegroundColor:Red -BackgroundColor Black
        }
    } catch {
        # Calculate variables
        $probe.name -match "^([a-z]{2})-([a-z]{3})-[a-z]{2}ng(p?)([d0-9])zz([0-9]{2,3})-([0-2]{2})" | Out-Null
        $dcPrefix = $Matches[1]
        $city = $Matches[2]
        $isPre = $Matches[3]
        $siteDigit = $Matches[4]
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
        if ($city -eq "rhr")
        {
            $dc = "rhr"
        }
        else {
            $dc = "ber"
        }
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

        # Exception for PRE
        if ( ($isPre -eq "p") -and ($siteDigit -gt 2) )
            {
                $site = "pre2"
            }

        # Get vCenter and connect
        if ($probe.vcenter -eq ""){
			$destVcenter = $probe.cluster.Split("-")[0] + "-" + $probe.cluster.Split("-")[1] + ".por-ngcs.lan"
		}else{
			$destVcenter = "$($probe.vcenter).por-ngcs.lan"
		}
        Write-Host "We are about to connect to $destVcenter to create $($probe.name)!`n" -ForegroundColor Cyan -BackgroundColor Blue
        #$vcenter = Connect-VIServer -Server $destVcenter -Credential $myCredentials -WarningAction:SilentlyContinue
        Connect-VIServer -Server $destVcenter -Credential $myCredentials -WarningAction:SilentlyContinue

        # Calculate datastore basing on probe name
        if ($probe.datastore -eq ""){
			if ($probe.name -like "*-01")
			{
				if ($dc -eq "rhr")
				{
					$datastore = "ds_${site}_site_internal3_01"
				}
				elseif ($dc -like "pr*")
				{
					$datastore = "ds_pre1_site_internal1_01"    
				}
				else
				{
					$datastore = "ds_${site}_site_internal1_01"
				}            
			}
			elseif ($probe.name -like "*-02")
			{
				if ($dc -like "pr*")
				{
					$datastore = "ds_pre1_site_internal2_01"
				}
				else
				{
				$datastore = "ds_${site}_site_internal2_01"
				}
			}
		}else{
			$datastore=$probe.datastore
		}
        # Prepare customization and deploy VM
        Get-OSCustomizationSpec -Name $probe.name -ErrorAction SilentlyContinue | Remove-OSCustomizationSpec -Confirm:$false
        #Write-Host  "`$oscust = New-OSCustomizationSpec -Name $($probe.name) -Type NonPersistent -OSCustomizationSpec $customization"
        $oscust = New-OSCustomizationSpec -Name $probe.name -Type NonPersistent -OSCustomizationSpec $customization
        $oscust | Get-OSCustomizationNicMapping | Set-OSCustomizationNicMapping -IpMode UseDhcp
        if ($createdns) {
            # Creamos el registro DNS, las windows no hace falta pues se auto-registran
            Write-Host "Vamos a conectar al Servidor de DNS para crear el registro"
            $dnscred = New-Object System.Management.Automation.PSCredential ($DomainProvisioningUser, (ConvertTo-SecureString $DomainProvisioningPass -AsPlainText -Force))
            Invoke-Command -ComputerName por-dc1.por-ngcs.lan -Credential $dnscred -ScriptBlock { Param($vmname, $vmip) Add-DNSServerResourceRecordA -ZoneName "por-ngcs.lan" -Name $vmname -IPv4Address $vmip -CreatePtr } -ArgumentList $($probe.name), $($probe.ipadd4) >> $null
    
        }
        #$vm = New-VM -Server $vcenter -Name $probe.name -Template (Get-template -Name $template) -ResourcePool (Get-Cluster -Name $probe.cluster) -OSCustomizationSpec $oscust -Datastore $datastore -Location (Get-Folder -Name $location -Type "VM")
        $vm = New-VM -Server $destVcenter -Name $probe.name -Template (Get-template -Name $template) -ResourcePool (Get-Cluster -Name $probe.cluster) -OSCustomizationSpec $oscust -Datastore $datastore -Location (Get-Folder -Name $location -Type "VM")
        Get-NetworkAdapter -VM (Get-VM -Name $probe.name) | Set-NetworkAdapter -NetworkName $probe.portgroup -Confirm:$false -StartConnected:$true
        Get-VM -Name $probe.name | Set-VM -NumCpu $numcpu -MemoryGB $ram -Confirm:$false
        if ($probe.privnet -ne "")
        {
            New-NetworkAdapter -VM $vm -Portgroup (Get-VDPortgroup -Name $probe.privnet) -StartConnected:$true -Type:Vmxnet3 -Confirm:$false
        }
        # Start-VM -Server $vcenter -VM $probe.name
        # Export MAC address to the CSV file
        # Add the information of VM and MAC address to a variable
        
        $probe.mac = (get-vm -Name $probe.name | Get-NetworkAdapter -Name "Network adapter 1").MacAddress
                
        Disconnect-VIServer -Server $destVcenter -Confirm:$false
    }
}

#Disconnect-VIServer -Server $destVcenter -Confirm:$false

# Export the array to our CSV
#$probeList | Export-csv -UseQuotes AsNeeded $probeFile
$probeList | Export-csv -Delimiter ',' -NoTypeInformation $probeFile

# DHCP reservation

$local_ssh = [bool] (Get-Command -ErrorAction Ignore -Type Application ssh)
#$vlanfordhcp = (($probe.portgroup) -split "vm")[1]

Write-Host "Connecting to DHCP Server to do the reservation, accept the SSH fingertprint for the first time `n`n" -ForegroundColor Cyan -BackgroundColor Blue
function ssh_exec {

    foreach ($probe in $probeList) 
        {
            $vlanfordhcp = (($probe.portgroup) -split "vm")[1]
            ssh -i $priv_key pssuser@$($probe.dhcpfqdn) "/home/pssuser/insert_dhcp_entry.sh -ipv4 $vlanfordhcp $($probe.mac) $($probe.ipadd4) && /home/pssuser/insert_dhcp_entry.sh -ipv6 $vlanfordhcp $($probe.mac) $($probe.ipadd6)"
            Write-Host "Correctly reserved $($probe.ipadd4) and $($probe.ipadd6) in $($vlanfordhcp) for VM $($probe.name) with MAC $($probe.mac) on $($robe.dhcpfqdn) `n" -ForegroundColor Green -BackgroundColor Blue
        }  
}

function plink_exec {

    foreach ($probe in $probelist)
    {
        $vlanfordhcp = (($probe.portgroup) -split "vm")[1]
        plink -batch -i $priv_key pssuser@$($probe.dhcpfqdn) "/home/pssuser/insert_dhcp_entry.sh -ipv4 $vlanfordhcp $($probe.mac) $($probe.ipadd4) && /home/pssuser/insert_dhcp_entry.sh -ipv6 $vlanfordhcp $($probe.mac) $($probe.ipadd6)"
        Write-Host "Correctly reserved $($probe.ipadd4) and $($probe.ipadd6) in $($vlanfordhcp) for VM $($probe.name) with MAC $($probe.mac) on $($robe.dhcpfqdn) `n" -ForegroundColor Green -BackgroundColor Blue

    }      
}

if ( $local_ssh )
{
    ssh_exec
}
else 
{
    plink_exec    
}

Write-Host "CMK Probes correctly deployed, now you must ensure to create the anti-spoofing rules with the MACs on your CSV File$($probeFile) " -ForegroundColor Green -BackgroundColor Black