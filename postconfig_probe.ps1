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

function Check-NetConnection($computername,$port,$timeout=200,$verbose=$false) {
            $tcp = New-Object System.Net.Sockets.TcpClient;
            try {
                $connect=$tcp.BeginConnect($computername,$port,$null,$null)
                $wait = $connect.AsyncWaitHandle.WaitOne($timeout,$false)
                if(!$wait){
                    $null=$tcp.EndConnect($connect)
                    $tcp.Close()
                    if($verbose){
                        Write-Host "Connection Timeout" -ForegroundColor Red
                        }
                    Return $false
                }else{
                    $error.Clear()
                    $null=$tcp.EndConnect($connect) # Dispose of the connection to release memory
                    if(!$?){
                        if($verbose){
                            write-host $error[0].Exception.Message -ForegroundColor Red
                            }
                        $tcp.Close()
                        return $false
                        }
                    $tcp.Close()
                    Return $true
                }
            } catch {
                return $false
            }
}

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
$myCredentials = Get-Credential -WarningAction:SilentlyContinue -Message "Please provide credentials from @ionos.com to connect to vcenter" -username "@ionos.com"

foreach ($probe in $probeList)
{
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
    Write-Host "Connecting to $destVcenter to power on $($probe.name) " -ForegroundColor Cyan -BackgroundColor Blue
    #$vcenter = Connect-VIServer -Server $destVcenter -Credential $myCredentials -WarningAction:SilentlyContinue        
    Connect-VIServer -Server $destVcenter -Credential $myCredentials -WarningAction:SilentlyContinue        
    Start-VM -Server $destVcenter -VM $($probe.name)
               
    Disconnect-VIServer -Server $destVcenter -Confirm:$false
    
}


#Disconnect-VIServer -Server $destVcenter -Confirm:$false

# SSH credential for default secret

$securepassword = Read-host -Prompt "Please, introduce the default password for root user in NGCS to connect over SSH" -AsSecureString
$sshpass = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($securepassword))

# Variables for Foreman REST API
        

#$password_ngcs = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($password_ngcs))
$porngcscreds = Get-Credential -WarningAction:SilentlyContinue -Message "Please provide credentials from @por-ngcs.lan to connect to remote desktop" -username "@por-ngcs.lan"
$porngcsruser = ($porngcscreds.username).Split("@")[0]
$porngcspassword = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($porngcscreds.password))

$ngcs_creds = $porngcsruser + ":" + $porngcspassword
$bytes = [System.Text.Encoding]::UTF8.GetBytes($ngcs_creds)
$encodedlogin=[Convert]::ToBase64String($bytes)
$authheader = "Basic " + $encodedlogin

# Add each host to his Foreman HostGroup and Environment depending from his site

foreach ($probe in $probeList)
{
    # Define the environment id depending if it's AC1 or PUB

    if ($isPre)
    {
        $env_id = 3
    }
    else {
        $env_id = 7
    }

    $probefqdn = $($probe.name) + ".por-ngcs.lan"

    $server = $probefqdn
    $port = 22

    do {
        Write-Host "Waiting for server to respond over SSH ..."
        Start-Sleep 3      
      } until(Check-NetConnection -computerName $server -Port $port)

    if ({ $_.TcpTestSucceeded } -eq "True") {

        Write-Host "Server $(server) is responding"
        
    }
        
    # Force puppet agent for the first time to register against Foreman

    if ($isPre){
    Write-Output y | plink -pw $sshpass -ssh -l root $probefqdn "exit"
    plink -batch -pw $sshpass -l root $probefqdn "puppet agent -t"
        Write-Host "Force Puppet agent to refresh in $($probe.name)" -ForegroundColor Green
    }
    else {
        Write-Output y | plink -pw $sshpass -ssh -l root $probefqdn "exit"
    plink -batch -pw $sshpass -l root $probefqdn "sed -i '/DNS1\|DNS2/d' /etc/sysconfig/network-scripts/ifcfg-ens192"
    plink -batch -pw $sshpass -l root $probefqdn "echo -e "nameserver 212.227.123.16" > /etc/resolv.conf"
    plink -batch -pw $sshpass -l root $probefqdn "echo -e "nameserver 212.227.123.17" >> /etc/resolv.conf"
    plink -batch -pw $sshpass -l root $probefqdn "puppet agent -t --server ngcs-puppet2.com.schlund.de --waitforcert 5"
        Write-Host "Force Puppet agent to refresh in $($probe.name)" -ForegroundColor Green
    }

        
     # Searching for HostGroupID of NGCS_PROBE over Foreman REST API

    $params_search_hostgroup = @{
    Uri         = "https://por-puppet2.por-ngcs.lan/api/hostgroups`?search=name=`"ngcs_probe`""
    Headers     = @{ 'Authorization' = $authheader }
    Method      = 'GET'
    ContentType = 'application/json'
                                }

    $response_api_hostgroups = Invoke-RestMethod @params_search_hostgroup 

    #$idhostgroup = ($response_api_hostgroups.results | select-object -property id,title | where-object {$_.title -like "*$($site)*"} ).id
    $idhostgroup = ($response_api_hostgroups.results | Select-Object -Property id,title | Where-Object -FilterScript {$_.title -like "*$site*"} ).id

    Write-Host " The hostgroup is $idhostgroup "

    # Searching for HostID over Foreman REST API

    $params_idhost = @{
        Uri         = "https://por-puppet2.por-ngcs.lan/api/hosts`?search=name=`"$($probe.name).por-ngcs.lan`""
        Headers     = @{ 'Authorization' = $authheader }
        Method      = 'GET'
        ContentType = 'application/json'
    }

    $response_api_idhost = Invoke-RestMethod @params_idhost

    $idhost = $response_api_idhost.results.id

    Write-Host " And HostID is $idhost "


     # Update HostGroup ID for host over Foreman REST API
    <#$Body_HostGroup = @{
        host = @(
          @{ 
            hostgroup_id =  $idhostgroup
          }
        )
      }
    #>
    #$jsonpayload_hostgroup = ($Body_HostGroup | ConvertTo-Json -Depth 10)
    $jsonpayload_hostgroup = "{ `"host`": { `"hostgroup_id`": $idhostgroup } }"

    $params_hostgroup = @{
        Uri         = "https://por-puppet2.por-ngcs.lan/api/hosts/$($idhost)"
        Headers     = @{ 'Authorization' = $authheader }
        Method      = 'PUT'
        Body        = $jsonpayload_hostgroup 
        ContentType = 'application/json'
    }
    
    $response_api_hostgroup = Invoke-RestMethod @params_hostgroup

    if ($response_api_hostgroup.hostgroup_id -eq $idhostgroup)
    {
        Write-Host "Added $($probe.name) to Foreman Hostgroup $($idhostgroup) for Site $($site)"    
    }else{
        Write-Error "Error contacting with Foreman API"
    }

    # Setting environment on host over Foreman and verify result
    $jsonpayload_env_id = "{ `"host`": { `"environment_id`": $env_id } }"
    
    $params_env_id = @{
        Uri         = "https://por-puppet2.por-ngcs.lan/api/hosts/$($idhost)"
        Headers     = @{ 'Authorization' = $authheader }
        Method      = 'PUT'
        Body        = $jsonpayload_env_id 
        ContentType = 'application/json'
    }

    $response_api_env_id = Invoke-RestMethod @params_env_id

    if ($response_api_env_id.environment_id -eq $env_id)
    {
        Write-Host "Added $($probe.name) to Foreman environment $($env_id) for Site $($site)"    
    }else{
        Write-Error "Error contacting with Foreman API"
    }
    
    # Verify if env is PRE(AC1) to execute puppet directly, if it's PUB (else) then select the puppet public server 
    if ($isPre)
    {
        plink -batch -pw $sshpass root@$probefqdn "puppet agent -t"
        Write-Host "Force Puppet agent to refresh in $($probe.name)" -ForegroundColor Green
    }
    else {
        plink -batch -pw $sshpass root@$probefqdn "puppet agent -t --server ngcs-puppet2.com.schlund.de --waitforcert 5"
        Write-Host "Force Puppet agent to refresh in $($probe.name)" -ForegroundColor Green
    }
}


Write-Host "Successfully postconfigured all VM's from $($probeFile)"