Param(
    [Parameter(Mandatory = $True)] [string]$probeFile = "",
    [Boolean]$force = $false,
    [Boolean]$createdns = $true
)

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
        $destVcenter = $probe.cluster.Split("-")[0] + "-" + $probe.cluster.Split("-")[1] + "por-ngcs.lan"
        Write-Host "We are about to connect to $vcenter to create $($probe.name)!"
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
            Invoke-Command -ComputerName por-dc1.por-ngcs.lan -Credential $dnscred -ScriptBlock { Param($vmname, $vmip) Add-DNSServerResourceRecordA -ZoneName "por-ngcs.lan" -Name $vmname -IPv4Address $vmip -CreatePtr } -ArgumentList $probe.name, $probe.ipadd >> $null
        }
        $vm = New-VM -Server $vcenter -Name $probe.name -Template (Get-template -Name $template) -ResourcePool (Get-Cluster -Name $probe.cluster) -OSCustomizationSpec $oscust -Datastore $datastore -Location (Get-Folder -Name $location -Type "VM")
        Get-NetworkAdapter -VM (Get-VM -Name $probe.name) | Set-NetworkAdapter -NetworkName $probe.portgroup -Confirm:$false -StartConnected:$true
        Get-VM -Name $probe.name | Set-VM -NumCpu $numcpu -MemoryGB $ram -Confirm:$false
        if ($probe.privnet -ne "")
        {
            New-NetworkAdapter -VM $vm -Portgroup (Get-VDPortgroup -Name $probe.privnet) -StartConnected:$true -Type:Vmxnet3 -Confirm:$false
        }
        # Start-VM -Server $vcenter -VM $probe.name
        
        # Add the information of VM and MAC address to a variable
        Disconnect-VIServer -Server $destVcenter -Confirm:$false
    }
}
