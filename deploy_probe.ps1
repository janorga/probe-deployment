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
.PARAMETER priv_key
Mandatory
Specify the path to your rsa private key file for the PSS User , if you use Windows 10/2K19 you must provide it with RSA format, if not then PPK file for the PLINK utility.
.EXAMPLE
.\deploy_probe.ps1 -probeFile pathdeprobefile -priv_key pathofyourrsakeypssuser
Execute the script with the path to your CSV file and the RSA priv key for PSS User with default DNS registry creation.
.EXAMPLE
.\deploy_probe.ps1 -probeFile pathdeprobefile -priv_key pathofyourrsakeypssuser -createdns false
Execute the script with the path to your CSV file and the RSA priv key for PSS User and no DNS registry creation.
.LINK 
Online version: https://confluence.united-internet.org/display/~jlobatoalonso/deploy+probe+script
.NOTES
2021 Javier Lobato 
2021/09/22 First Release
#>

Param(
    [Parameter(Mandatory = $True)] [string]$probeFile = "",
    [Parameter(Mandatory = $True)] [string]$priv_key = "",
    [Boolean]$force = $false,
    [Boolean]$createdns = $true
    )

if (!$probeFile){
    Write-Host "Please, give the path to the CSV file with all parameters as the proble_example.csv file in the DATA directory !" -ForegroundColor Red
	exit 10
}

if (!$priv_key){
    Write-Host "Please, give the path to your private key file for PSSUSER in PPK format or RSA if you are using Win10/2K19 !" -ForegroundColor Red
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

# Default variables
$DomainProvisioningUser="DomainProvisioning@por-ngcs.lan"
$DomainProvisioningPass="KI/%43e42ku7t412MHJG2..71fEWS(fd"
$location = "network"
$template = "co7_64_puppet5"
$customization = "por-generic"
$numcpu = 1
$ram = 2

#Ask for credentials and connect to vCenter
$myCredentials = Get-Credential -Message "Type user credentials for the vCenter connection"

foreach ($probe in $probeList)
{
    try {
        if ( $force ) {
            throw "Forced re-creation of VM and DNS entries"
        } else {
            # Will be replaced by Resolve-DnsName if powershell is upgraded in desktops
            $dnscheck = [System.Net.DNS]::GetHostAddresses("$($probe.name).por-ngcs.lan")
            Write-Host "DNS entry already exists. Please check and re-run script with -force:`$true option" -ForegroundColor:Red
        }
    } catch {
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

        # Get vCenter and connect
        $destVcenter = $probe.cluster.Split("-")[0] + "-" + $probe.cluster.Split("-")[1] + ".por-ngcs.lan"
        Write-Host "We are about to connect to $($vcenter) to create $($probe.name)!"
        $vcenter = Connect-VIServer -Server $destVcenter -Credential $myCredentials -WarningAction:SilentlyContinue        

        # Calculate datastore basing on probe name
        if ($probe.name -like "*-01")
        {
            if ($dc -eq "rhr")
            {
                $datastore = "ds_${site}_site_internal3_01"
            }
            else
            {
                $datastore = "ds_${site}_site_internal1_01"
            }            
        }
        else
        {
            $datastore = "ds_${site}_site_internal2_01"
        }

        # Prepare customization and deploy VM
        Get-OSCustomizationSpec -Name $probe.name -ErrorAction SilentlyContinue | Remove-OSCustomizationSpec -Confirm:$false
        $oscust = New-OSCustomizationSpec -Name $probe.name -Type NonPersistent -OSCustomizationSpec $customization
        $oscust | Get-OSCustomizationNicMapping | Set-OSCustomizationNicMapping -IpMode UseDhcp
        if ($createdns) {
            # Creamos el registro DNS, las windows no hace falta pues se auto-registran
            Write-Host "Vamos a conectar al Servidor de DNS para crear el registro"
            $dnscred = New-Object System.Management.Automation.PSCredential ($DomainProvisioningUser, (ConvertTo-SecureString $DomainProvisioningPass -AsPlainText -Force))
            Invoke-Command -ComputerName por-dc1.por-ngcs.lan -Credential $dnscred -ScriptBlock { Param ($vmname, $vmip) Add-DNSServerResourceRecordA -ZoneName "por-ngcs.lan" -Name $vmname -IPv4Address $vmip -CreatePtr } -ArgumentList $probe.name $probe.ipadd4 >> $null
        }
        $vm = New-VM -Server $vcenter -Name $probe.name -Template (Get-template -Name $template) -ResourcePool (Get-Cluster -Name $probe.cluster) -OSCustomizationSpec $oscust -Datastore $datastore -Location (Get-Folder -Name $location -Type "VM")
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

# Export the array to our CSV
$probeList | Export-csv -UseQuotes AsNeeded $probeFile

# DHCP reservation

$local_ssh = [bool] (Get-Command -ErrorAction Ignore -Type Application ssh)
$vlanfordhcp = (($probe.portgroup) -split "vm")[1]

Write-Host "Connecting to DHCP Server to do the reservation, accept the SSH fingertprint for the first time" -ForegroundColor Cyan
function ssh_exec {

    foreach ($probe in $probeList) 
    {
        ssh -i $priv_key pssuser@$($probe.dhcpfqdn) "/home/pssuser/insert_dhcp_entry.sh -ipv4 $vlanfordhcp $($probe.mac) $($probe.ipadd4) && /home/pssuser/insert_dhcp_entry.sh -ipv6 $vlanfordhcp $($probe.mac) $($probe.ipadd6)"
        Write-Host "Correctly reserved $($probe.ipadd4) and $($probe.ipadd6) in $($vlanfordhcp) for NIC with MAC $($probe.mac) on $($robe.dhcpfqdn)" -ForegroundColor Green
    }  
}

function plink_exec {

    foreach ($probe in $probelist)
    {
        plink -batch -i $priv_key pssuser@$($probe.dhcpfqdn) "/home/pssuser/insert_dhcp_entry.sh -ipv4 $vlanfordhcp $($probe.mac) $($probe.ipadd4) && /home/pssuser/insert_dhcp_entry.sh -ipv6 $vlanfordhcp $($probe.mac) $($probe.ipadd6)"
        Write-Host "Correctly reserved $($probe.ipadd4) and $($probe.ipadd6) in $($vlanfordhcp) for NIC with MAC $($probe.mac) on $($robe.dhcpfqdn)" -ForegroundColor Green

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