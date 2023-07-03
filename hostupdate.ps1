#region parameters
# Modules
Import-Module HPEOneView.660
Import-Module HPEiLOCmdlets
Import-module GlobalDashboardPS

get-module HPEiLOCmdlets

#PARAMETERS
$targetCluster = ""
#$targetHostProfileG9 = ""
#$targetHostProfileG10 = ""
$targetHostProfile = ""
$targetHpovIp = ""
$MaintenanceTime = 480 #in minuten
$vSphere7LicKey = ""
$vSphere7LicKey = ""


$when = Get-Date -format "ddMMyyyy"
$what = "Deployment"
$sreason = "EricH-$when-$what"

#Gen9
$iLoFwFilegen9 = ".bin"
$reqIloVersiongen9 = ""
#$sppurlGen9 = ".iso"
#gen10
$iLoFwFilegen10 = ""
$reqIloVersiongen10 = ""
#$sppurlGen10 = ""

#CREDENTIALS - run as [name]
$personalUser = "[name]"
$personalDomainPwFile = "U:\curapw.txt"
$iloUser = "HOSTING" 
$iloPwFile = "U:\ilohostingpw.txt"
$esxirootpwFile = "U:\esxirootpw.txt"
$vropsCred=New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $personalUser, (Get-Content $personalDomainPwFile | ConvertTo-SecureString)
$vcenterCred = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $("Cura\$personalUser"), (Get-Content $personalDomainPwFile | ConvertTo-SecureString)
$iloCred = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $iloUser, (Get-Content $iloPwFile | ConvertTo-SecureString)
$esxirootcred = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList "root", (Get-Content $esxirootpwFile | ConvertTo-SecureString)
# --> (Get-Credential).Password | ConvertFrom-SecureString | Out-File $personalDomainPwFile



#CONNECTIONS
#VCENTER
#disconnect-VIServer *
Connect-VIServer -Credential $vcenterCred [vcenter]
#CONNECT VROPS
Connect-OMServer [vrops] -Credential $vropsCred -AuthSource [domain FQDN]
#Connect OneView
Connect-OVMgmt -Hostname $targetHpovIp -Credential $vropsCred -AuthLoginDomain [domain FQDN]
#Disconnect-OVMgmt 

#endregion parameters



#region SelectHosts
#GET HOSTS
$targetHosts = Get-Cluster $targetCluster|Get-VMHost|Sort-Object
$targetVropsHosts = $targetHosts|Get-OMResource 
$targetHosts |select Name,ConnectionState,build,version,Parent|ft

# tegelijk patchen
$targetHostsToDo = get-vmhost 
$targetHostsToDo|select Name,ConnectionState,build,version
$targetVropsHosts = $targetHostsToDo|Get-OMResource 
#endregion SelectHosts



#region StateCHange
#IN MAINTENANCE - EXECUTE SEPERATELY
$targetVropsHosts.ExtensionData.MarkResourceAsBeingMaintained($MaintenanceTime)
$targetHostsToDo | Set-Annotation -CustomAttribute "Maintenance" -Value $sreason
#$targetHostsToDo | Get-Annotation -CustomAttribute "Maintenance" 


#$targetHosts | Get-Annotation -CustomAttribute "Maintenance"|where $_.Value -like "EricH-*-SDcard"
#$targetHostsToClear = $targetHosts|Where-Object {($_ |get-Annotation -CustomAttribute "Maintenance").Value -like "EricH*"}
#$targetHostsToClear |Set-Annotation -CustomAttribute "Maintenance" -Value ""
#$targetHostsToClear| Get-Annotation -CustomAttribute "Maintenance"
    
     
                                              
############# CHOOSE ONE - CAREFULL!
# ENTER MAINT
$targetHostsToDo|set-vmhost -State Maintenance -evacuate:$true
# EXIT MAINT
$targetHostsToDo|set-vmhost -State Connected
# POWER OFF
$targetHostsToDo|stop-VMHost -Reason $sreason 
# REBOOT
$targetHostsToDo|restart-VMHost -Reason $sreason
#endregion StateCHange



#UIT MAINTENANCE - EXECUTE SEPERATELY
$targetVropsHosts.ExtensionData.UnmarkResourceAsBeingMaintained()
$targetHostsToDo | Set-Annotation -CustomAttribute "Maintenance" -Value ""
#$targetHosts | Get-Annotation -CustomAttribute "Maintenance"


# START SSH + DISABLE LOCKDOWN
foreach($targetHostToDo in $targetHostsToDo){Start-VMHostService -HostService ($targetHostToDo | Get-VMHostService | Where-Object {$_.key -eq "TSM-SSH"}) -Confirm:$false | Select-Object VMHost,Key,Label,Running}
foreach($targetHostToDo in $targetHostsToDo){($targetHostToDo | Get-View).ExitLockdownMode()}

# START PUTTY
foreach($targetHostToDo in $targetHostsToDo){putty $targetHostToDo.Name}

# STOP SSH + # ENABLE LOCKDOWN
foreach($targetHostToDo in $targetHostsToDo){Stop-VMHostService -HostService ($targetHostToDo | Get-VMHostService | Where-Object {$_.key -eq "TSM-SSH"}) -Confirm:$false | Select-Object VMHost,Key,Label,Running}
foreach($targetHostToDo in $targetHostsToDo){($targetHostToDo | Get-View).EnterLockdownMode()}

#Disable SLP
# https://communities.vmware.com/t5/vSphere-Upgrade-Install/Powercli-Options-To-Disable-SFCB-and-SLP-Services/ta-p/2857164
$targetHostsToDo|Get-VMHostService | Where {$_.Key –eq "slpd”}| Stop-VMHostService -Confirm:$false
$targetHostsToDo|Get-VMHostService | Where {$_.Key –eq "slpd”} | Set-VMHostService -Policy Off -Confirm:$false




#region  RemoveVIB
$targetVibName = "MIS_bootbank_hpessacli_5.30.6.0-6.7.0.7535516.oem"
foreach ($targetHostToDo in $targetHostsToDo)
{
    $targetVib = $null
    $targetHostToDoModel = $targetHostToDo.Model
    #if ($targetHostToDoModel -like "*Gen10"){
        $ESXCLI = Get-EsxCli -VMHost $targetHostToDo
        $targetVib = $ESXCLI.software.vib.list()|where-object {$_.ID -like $targetVibName}
        if ($targetVib -ne $null){
            write-host -ForegroundColor red $("Model is $targetHostToDoModel,$targetVibName will be removed")
            $esxcli.software.vib.remove($false,$true,$false,$true,$targetVib.Name)
        }else{write-host -ForegroundColor green $("Model is $targetHostToDoModel,$targetVibName not found,no action needed")}   
    #}else{write-host -ForegroundColor green $("Model is $targetHostToDoModel,no action needed")}
}
#endregion RemoveVIB





#ASSIGN LICENSE KEY
$targetHostsToDo| Select Name, LicenseKey
$targetHostsToDo|set-vmhost -LicenseKey $vSphere7LicKey
# Check ALL license keys
get-vmhost |where {$_.Licensekey -eq "00000-00000-00000-00000-00000"}

#Assign host profile
Invoke-VMHostProfile -AssociateOnly -Entity $targetHostsToDo -Profile $targetHostProfile
#Check Profile Compliance
$targetHostsToDo|Test-VMHostProfileCompliance


#REMEDIATE STATUS
get-task|where {$_.ServerId -like "*[name]*" -and ($_.Name -eq "Remediate entity" -or $_.Name -eq "Scan entity")}|Select State,PercentComplete,Description,@{ Name = 'Target'; Expression = { get-cluster -id $_.ObjectId }}


#placeholder VMs
#| Where-Object {$_.ExtensionData.Config.ManagedBy.Type -ne 'placeholderVm'}


#region DisableDRS
# AAN OF UIT
$targetDrsRulesEnable = $false
#
$cluster = Get-Cluster $targetCluster
$targetDrsRules = Get-DrsRule -Cluster $targetcluster -Type VMHostAffinity|Where-Object {$_.Name -eq "LinuxAffinity" -or $_.Name -like "Win*Affinity"}
$targetDrsRules
foreach ($targetDrsRule in $targetDrsRules){
    $spec = New-Object VMware.Vim.ClusterConfigSpec
    $ruleSpec = New-Object VMware.Vim.ClusterRuleSpec 
    $ruleSpec.Info = $targetDrsRule.ExtensionData 
    $ruleSpec.Info.Enabled = $targetDrsRulesEnable
    $ruleSpec.Operation = "edit"
    $spec.rulesSpec += $ruleSpec
    $cluster.ExtensionData.ReconfigureCluster($spec,$true)
}
Get-DrsRule -Cluster $targetcluster -Type VMHostAffinity|Where-Object {$_.Name -eq "LinuxAffinity" -or $_.Name -like "Win*Affinity"}
#endregion DisableDRS

#remove rules
#Get-DrsRule -Cluster $targetcluster -Type VMHostAffinity|Where-Object {$_.Name -eq "LinuxAffinity" -or $_.Name -like "Win*Affinity"} | Remove-DrsVMToVMHostRule 


#region SynergyUpdate
foreach($targetHostToDo in $targetHostsToDo){
    $targetHostToDoShort = ($targetHostToDo.Name).Split(".")[0]
    $targetSynergyProfile = Get-HPOVServerProfile -Name $targetHostToDoShort
    Update-HPOVServerProfile -InputObject $targetSynergyProfile -Async
    }
#endregion SynergyUpdate



#region INTASK7113420
# rollback mitigation
$targetAvdSettings = @{
    "VMkernel.Boot.Hyperthreading" = $True
    "VMkernel.Boot.HyperthreadingMitigation"  = $False
    "VMkernel.Boot.HyperthreadingMitigationintraVM" = $True
}
foreach($targetHostToDo in $targetHostsToDo){
    foreach ($targetAvdSetting in $targetAvdSettings.GetEnumerator()) {
        If ((Get-AdvancedSetting -Entity $targetHostToDo -Name $targetAvdSetting.Name).Value -ne $targetAvdSetting.Value){
            (get-AdvancedSetting -Entity $targetHostToDo -Name $targetAvdSetting.Name)|Set-AdvancedSetting -Value $targetAvdSetting.Value -Confirm:$false
            write-host -ForegroundColor red "$($targetAvdSetting.Name) corrected to $($targetAvdSetting.Value) - please reboot"
        }else{
            write-host -ForegroundColor green "$($targetAvdSetting.Name) $($targetAvdSetting.Value) - ok"
        }
    }
} 
#endregion INTASK7113420




#region AdvancedModeSettings
$targetAvdSettings = @{
    "VMkernel.Boot.Hyperthreading" = $True
    "VMkernel.Boot.HyperthreadingMitigation"  = $True
    "VMkernel.Boot.HyperthreadingMitigationintraVM" = $False
}
foreach($targetHostToDo in $targetHostsToDo){
    foreach ($targetAvdSetting in $targetAvdSettings.GetEnumerator()) {
        If ((Get-AdvancedSetting -Entity $targetHostToDo -Name $targetAvdSetting.Name).Value -ne $targetAvdSetting.Value){
            (get-AdvancedSetting -Entity $targetHostToDo -Name $targetAvdSetting.Name)|Set-AdvancedSetting -Value $targetAvdSetting.Value -Confirm:$false
            write-host -ForegroundColor red "$($targetAvdSetting.Name) corrected to $($targetAvdSetting.Value) - please reboot"
        }else{
            write-host -ForegroundColor green "$($targetAvdSetting.Name) $($targetAvdSetting.Value) - ok"
        }
    }
} 
#endregion AdvancedModeSettings



#region  ListVIB
$result = @()
foreach ($targetHostToDo in $targetHosts)
{
    $targetHostToDo.Name
    $ESXCLI = Get-EsxCli -VMHost $targetHostToDo
    $targethostVibResult = $ESXCLI.software.vib.list()|Where-Object {$_.ID -like "*smx*"} |select Name,ID,Version,@{Name='Host';Expression={$targetHostToDo.Name}},@{Name='Cluster';Expression={$targetHostToDo.Parent}},@{Name='Mode';Expression={$targetHostToDo.Model}}
    $result += $targethostVibResult
}
#$result|export-csvS C:\temp\qfle3vib.csv
$result|ft
#endregion ListVIB


#region BIOSsettings
foreach($targetHostToDo in $targetHostsToDo){
    $targetHostToDoShort = ($targetHostToDo.Name).Split(".")[0]
    $targetHostToDoShort
    #$targetIloIP = (Get-OVServer -ServerName $targetHostToDo).mpHostInfo.mpIpAddresses[0].address
    $targetIloIP = ((Get-OVServer -ServerName $targetHostToDo).mpHostInfo.mpIpAddresses|where-object {$_.address -like "*.*"}).address
    $targetIloIP

    #Connect to target BIOS
    $targetBios = Connect-HPEBIOS $targetIloIP -DisableCertificateAuthentication -Credential $iloCred
  
    #Ilo5 rechten corrigeren
    if($targetBios.TargetInfo.iLOGeneration -eq "iLO5"){
        write-host -ForegroundColor red $("correcting iLO5 permissions")
        Set-HPEiLOUser -Connection $targetBios -LoginName HOSTING -HostBIOSConfigPrivilege Yes -HostNICConfigPrivilege Yes -HostStorageConfigPrivilege Yes
    }else{
        write-host -ForegroundColor green $("not iLO5 so no permissions corrected")
    }

    #gen9 Check and Correct PowerProfile
    if($targetBios.TargetInfo.ServerGeneration -eq "Gen9"){
        $targetBiosPowerProfile = (Get-HPEBIOSPowerProfile -Connection $targetBios).PowerProfile
        if($targetBiosPowerProfile -ne "MaximumPerformance"){
            Set-HPEBIOSPowerProfile -Connection $targetBios -PowerProfile "MaximumPerformance"
            write-host -ForegroundColor red $("corrected gen9 Powerprofile $targetBiosPowerProfile to MaximumPerformance")
        }else{
            write-host -ForegroundColor green $("gen9 Powerprofile $targetBiosPowerProfile is Correct")
        }
    }

    #Gen10 Check gen10 and correct WorkloadProfile
    if($targetBios.TargetInfo.ServerGeneration -eq "Gen10"){
        $targetBiosWorkloadProfile = (Get-HPEBIOSWorkloadProfile -Connection $targetBios).WorkloadProfile
        if($targetBiosWorkloadProfile -ne "VirtualizationMaximumPerformance"){
            Set-HPEBIOSWorkloadProfile -Connection $targetBios -WorkloadProfile "VirtualizationMaximumPerformance"
            write-host -ForegroundColor red $("corrected gen10 WorkloadProfile $targetBiosWorkloadProfile to VirtualizationMaximumPerformance")
        }else{
            write-host -ForegroundColor green $("gen10 WorkloadProfile $targetBiosWorkloadProfile is Correct")
        }
    }

    #Check and Correct Bootmode
    $targetBiosBootMode = (Get-HPEBIOSBootMode -Connection $targetBios).Bootmode
    if($targetBiosBootMode -ne "UEFIMode"){
        Set-HPEBIOSBootMode -Connection $targetBios -BootMode "UEFIMode"
        write-host -ForegroundColor red $("corrected Bootmode $targetBiosBootMode to UEFIMode")
    }else{
        write-host -ForegroundColor green $("Bootmode $targetBiosBootMode is Correct")
    }
    
    #Check and correct NTP settings
    $targetBiosNtp = $targetBios | Get-HPEiLOSNTPSetting | select Hostname , IP, PropagateTimetoHost, Timezone
    if($targetBiosNtp.PropagateTimetoHost -ne "Disabled" -or $targetBiosNtp.TimeZone -ne "Europe/Amsterdam"){
        $targetBios | Set-HPEiLOSNTPSetting -PropagateTimetoHost Disabled -Timezone Europe/Amsterdam
        write-host -ForegroundColor red $("NTPsettings corrected")
    }else{
        write-host -ForegroundColor green $("NTPsettings correct")
    }

    # Disconnect BIOS
    disConnect-HPEBIOS -Connection $targetBios

    # CHECK AND CORRECT iLO NETWORK NAME
    $targetIloNetworkname = (get-HPiLONetworkSetting -DisableCertificateAuthentication -Server $targetIloIP -Credential $iloCred).DNS_NAME
    $targetHostToDoShortCase = $targetHostToDoShort.ToUpper()
    if($targetIloNetworkname -cne $targetHostToDoShortCase){
        write-host -ForegroundColor red $("iLO network name $targetIloNetworkname will be corrected to $targetHostToDoShortCase")
        set-HPiLONetworkSetting -DisableCertificateAuthentication -Server $targetIloIP -Credential $iloCred -DNSName $targetHostToDoShortCase
    }else{
        write-host -ForegroundColor green $("iLO network name $targetIloNetworkname is correct,no action needed")
    }
}
#endregion BIOSsettings


#region iLOupgrade
foreach($targetHostToDo in $targetHostsToDo){
    $targetHostToDoShort = ($targetHostToDo.Name).Split(".")[0]
    $targetHostToDoShort
    $targetIloIP = (Get-HPOVServer -ServerName $targetHostToDo).mpHostInfo.mpIpAddresses[0].address
    $targetIloIP
    $targetIlo = Connect-HPEiLO -Credential $iloCred -DisableCertificateAuthentication -IP $targetIloIP
    
    # check FW gen9
    if($targetIlo.TargetInfo.iLOGeneration -eq "iLO4"){
        $targetIloVersion = ($targetIlo.TargetInfo.iLOFirmwareVersion).ToString()
        if($targetIloVersion -ne $reqIloVersiongen9){
            write-host -ForegroundColor Red $("ILO4 version $targetIloVersion is lower than $reqIloVersiongen9 starting upgrade")
            #Update-HPEiLOFirmware -Connection $targetIlo -Location $iLoFwFilegen9 -Confirm:$false
        }else{
            write-host -ForegroundColor Green $("ILO4 version $targetIloVersion is good, skipping upgrade")
        }
    }

    # check FW gen10
    if($targetIlo.TargetInfo.iLOGeneration -eq "iLO5"){
        $targetIloVersion = ($targetIlo.TargetInfo.iLOFirmwareVersion).ToString()
        if($targetIloVersion -ne $reqIloVersiongen10){
            write-host -ForegroundColor Red $("ILO5 version $targetIloVersion is lower than $reqIloVersiongen10 starting upgrade")
            #Update-HPEiLOFirmware -Connection $targetIlo -Location $iLoFwFilegen10 -Confirm:$false
        }else{
            write-host -ForegroundColor Green $("ILO5 version $targetIloVersion is good, skipping upgrade")
        }
    }
    #Disconnect
    Disconnect-HPEiLO -Connection $targetIlo
}
#endregion iLOupgrade


#region checkGen
foreach($targetHostToDo in $targetHostsToDo){
    $targetHostToDoShort = ($targetHostToDo.Name).Split(".")[0]
    $targetHostToDoShort
    $targetIloIP = (Get-HPOVServer -ServerName $targetHostToDo).mpHostInfo.mpIpAddresses[0].address
    $targetIloIP
    $targetIlo = Connect-HPEiLO -Credential $iloCred -DisableCertificateAuthentication -IP $targetIloIP
    
    # check Generation
    $targetIlo.TargetInfo.ServerGeneration

    #Disconnect
    Disconnect-HPEiLO -Connection $targetIlo
}
#endregion checkGen


#region SPP 
#--> MAKE SURE HFS WEBSERVER IS CONFIGURED!
foreach($targetHostToDo in $targetHostsToDo){
    $targetHostToDoShort = ($targetHostToDo.Name).Split(".")[0]
    $targetHostToDoShort
    $targetIloIP = ((Get-HPOVServer -ServerName $targetHostToDo.Name).mpHostInfo.mpIpAddresses|where-object {$_.address -like "*.*"}).address
    $targetIloIP
    #Connect to target BIOS
    $targetBios = Connect-HPEBIOS $targetIloIP -DisableCertificateAuthentication -Credential $iloCred

    set-HPiLOOneTimeBootOrder -Credential $iloCred -DisableCertificateAuthentication -Server $targetIloIP -Device CDROM
    Get-HPiLOOneTimeBootOrder -Credential $iloCred -DisableCertificateAuthentication -Server $targetIloIP

    #Gen9 
    if($targetBios.TargetInfo.ServerGeneration -eq "Gen9"){
        Mount-HPEiLOVirtualMedia -Connection $targetBios -Device CD -ImageURL $sppurlGen9
        (Get-HPEiLOVirtualMediaStatus -Connection $targetBios).VirtualMediaInformation
    }
    
    #Gen10
    if($targetBios.TargetInfo.ServerGeneration -eq "Gen10"){
        Mount-HPEiLOVirtualMedia -Connection $targetBios -Device CD -ImageURL $sppurlGen10
        (Get-HPEiLOVirtualMediaStatus -Connection $targetBios).VirtualMediaInformation
    }
    
    # Disconnect BIOS
    disConnect-HPEBIOS -Connection $targetBios
}
#endregion SPP


#region PowerOn
foreach($targetHostToDo in $targetHostsToDo){
    $targetHostToDoShort = ($targetHostToDo.Name).Split(".")[0]
    $targetHostToDoShort
    $targetIloIP = ((Get-HPOVServer -ServerName $targetHostToDoShort).mpHostInfo.mpIpAddresses|where-object {$_.address -like "*.*"}).address
    $targetIloIP
    #Connect to target BIOS
    $targetBios = Connect-HPEBIOS $targetIloIP -DisableCertificateAuthentication -Credential $iloCred
  
    Get-HPEiLOServerPower -Connection $targetBios
    Set-HPEiLOServerPower -Connection $targetBios -Power On
    
    # Disconnect BIOS
    disConnect-HPEBIOS -Connection $targetBios
}
#endregion PowerOn



#region ChangeEsxiHostname
foreach($targetHostToDo in $targetHostsToDo){
    # change ESXI hostname
    $targetHostToDoVcenterName = $targetHostToDo.Name.Split(".")[0]
    $targetHostToDoVMHostNetwork = Get-VMHostNetwork -VMHost $targetHostToDo
    $targetHostToDoVMHostNetworkHostname =  $targetHostToDoVMHostNetwork.HostName
    #$targetHostToDoVMHostNetwork|Set-VMHostNetwork -HostName $("$targetHostToDoVcenterName-temp")
    If($targetHostToDoVcenterName -ne $targetHostToDoVMHostNetworkHostname){
        write-host -ForegroundColor red $("changed ESXi hostname $targetHostToDoVMHostNetworkHostname to $targetHostToDoVcenterName")
        $targetHostToDoVMHostNetwork|Set-VMHostNetwork -HostName $targetHostToDoVcenterName
    }else{
        write-host -ForegroundColor green $("ESXi hostname $targetHostToDoVMHostNetworkHostname is correct")
    }
}
#endregion ChangeEsxiHostname


#region Misc
#ILO Security Settings
Get-HPEiLOEncryptionSetting -Connection $targetBios
#endregion Misc



#region CorrectEsxiDomainName
foreach($targetHostToDo in $targetHostsToDo){
    # check and change ESXI domainName
    $targetHostToDoVcenterDomainName = $targetHostToDo.Name.Split(".")[-2,-1] -join "."
    $targetHostToDoVMHostNetwork = Get-VMHostNetwork -VMHost $targetHostToDo
    $targetHostToDoVMHostNetworkDomain =  $targetHostToDoVMHostNetwork.DomainName
    If($targetHostToDoVcenterDomainName -ne $targetHostToDoVMHostNetworkDomain){
        write-host -ForegroundColor red $("ESXi $($targetHostToDoVMHostNetwork.HostName) - changed domainname from $targetHostToDoVMHostNetworkDomain to $targetHostToDoVcenterDomainName")
        #$targetHostToDoVMHostNetwork|Set-VMHostNetwork -DomainName $targetHostToDoVcenterDomainName
    }else{
        write-host -ForegroundColor green $("ESXi $($targetHostToDoVMHostNetwork.HostName) - domainname $targetHostToDoVMHostNetworkDomain is correct")
    }
}
#endregion CorrectEsxiDomainName



#region iLOTimeZone
foreach($targetHostToDo in $targetHostsToDo){
    $targetHostToDoShort = ($targetHostToDo.Name).Split(".")[0]
    $targetHostToDoShort
    $targetIloIP = ((Get-OVServer -ServerName $targetHostToDo.Name).mpHostInfo.mpIpAddresses|where-object {$_.address -like "*.*"}).address
    $targetIloIP
    #Connect to target BIOS
    $targetBios = Connect-HPEBIOS $targetIloIP -DisableCertificateAuthentication -Credential $iloCred

    #setTimezone
    $targetBios | Get-HPEiLOSNTPSetting | select Hostname , IP, PropagateTimetoHost, Timezone
    $targetBios | Set-HPEiLOSNTPSetting -PropagateTimetoHost Disabled -Timezone Europe/Amsterdam
    $targetBios | Get-HPEiLOSNTPSetting | select Hostname , IP, PropagateTimetoHost, Timezone
    Set-HPEiLOIPv6NetworkSetting -Connection $targetBios -Interfacetype Dedicated -DHCPv6DomainName Disabled -DHCPv6DNSServer Disabled -DHCPv6Stateful Disabled -DHCPv6RapidCommit Disabled -DHCPv6SNTPSetting Disabled -DHCPv6Stateless Disabled -StatelessAddressAutoConfiguration Disabled -RegisterDDNSServer Disabled -PreferredProtocol Disabled 
    get-HPEiLOIPv6NetworkSetting -Connection $targetBios
    # Disconnect BIOS
    disConnect-HPEBIOS -Connection $targetBios
}
#endregion iLOTimeZone






#region INC10927258

$targetHostsToDo = Get-Cluster $targetCluster|Get-VMHost|Sort-Object

$targetAvdSettings = @{
    "Syslog.global.defaultRotate" = "20"
}
foreach($targetHostToDo in $targetHostsToDo){
    foreach ($targetAvdSetting in $targetAvdSettings.GetEnumerator()) {
        If ((Get-AdvancedSetting -Entity $targetHostToDo -Name $targetAvdSetting.Name).Value -ne $targetAvdSetting.Value){
            (get-AdvancedSetting -Entity $targetHostToDo -Name $targetAvdSetting.Name)|Set-AdvancedSetting -Value $targetAvdSetting.Value -Confirm:$false
            write-host -ForegroundColor red "$($targetHostToDo) - $($targetAvdSetting.Name) corrected to $($targetAvdSetting.Value)"
        }else{
            write-host -ForegroundColor green "$($targetHostToDo) - $($targetAvdSetting.Name) $($targetAvdSetting.Value) - ok"
        }
    }
} 
#endregion INC10927258


#region efuse
get-hpovserver -ServerName [naam]
$targetEnclosure = Get-HPOVEnclosure -Name [naam]
$targetEnclosure.deviceBays|select ipv4Setting,baynumber
#reset-HPOVEnclosureDevice -Enclosure $targetEnclosure -Component Device -DeviceID 3 -Efuse
#endregion efuse



#region SDCARD
foreach($targetHost in $targetHostsToDo){
    $targetHostShort = ($targetHost.Name).Split(".")[0]
    $targetHostShort
    $targetIloIP = ((Get-HPOVServer -ServerName $targetHostShort).mpHostInfo.mpIpAddresses|where-object {$_.address -like "*.*"}).address

    #SDCARD uitvragen
    (Get-HPiLOSDCardStatus -Server $targetIloIP -DisableCertificateAuthentication  -Credential $iloCred).SDCARD_STATUS
}
#endregion SDCARD




#region powercap
foreach($targetHost in $targetHostsToDo){
    $targetHostShort = ($targetHost.Name).Split(".")[0]
    $targetHostShort
    $targetIloIP = ((Get-HPOVServer -ServerName $targetHost.Name).mpHostInfo.mpIpAddresses|where-object {$_.address -like "*.*"}).address
    $targetBios = Connect-HPEBIOS $targetIloIP -DisableCertificateAuthentication -Credential $iloCred
    $targetBios|Get-HPEiLOPowerCapSetting
}
#endregion powercap



# Orphaned VMs zoeken (SRM)
Get-VM * | Where {$_.ExtensionData.Summary.Runtime.ConnectionState -eq "orphaned"}






#region Power2023
foreach($targetHostToDo in $targetHostsToDo){
    # Controleren of het een Synergy betreft
    If ($targetHostToDo.Model -notlike "Synergy*"){

        #Connect to target BIOS
        $targetHostToDoShort = ($targetHostToDo.Name).Split(".")[0]
        $targetHostToDoShort
        $targetIloIP = ((Get-HPOVServer -ServerName $targetHostToDo.Name).mpHostInfo.mpIpAddresses|where-object {$_.address -like "*.*"}).address
        $targetIloIP
        $targetBios = Connect-HPEBIOS $targetIloIP -DisableCertificateAuthentication -Credential $iloCred

        #gen9 Check and Correct PowerProfile
        if($targetBios.TargetInfo.ServerGeneration -eq "Gen9"){
            # Check POwerProfile
            $targetBiosPowerProfile = (Get-HPEBIOSPowerProfile -Connection $targetBios).PowerProfile
            if($targetBiosPowerProfile -ne "Custom"){
                Set-HPEBIOSPowerProfile -Connection $targetBios -PowerProfile "Custom"
                write-host -ForegroundColor red $("corrected gen9 Powerprofile $targetBiosPowerProfile to Custom")
            }else{
                write-host -ForegroundColor green $("gen9 Powerprofile $targetBiosPowerProfile is Correct")
            }
            # Check PowerRegulator
            $targetBiosPowerRegulator = (Get-HPEBIOSPowerRegulator -Connection $targetBios).PowerRegulator
            if($targetBiosPowerRegulator -ne "OSControlMode"){
                Set-HPEBIOSPowerRegulator -Connection $targetBios -PowerRegulator "OSControlMode"
                write-host -ForegroundColor red $("corrected gen9 PowerRegulator $targetBiosPowerRegulator to OSControlMode")
            }else{
                write-host -ForegroundColor green $("gen9 PowerRegulator $targetBiosPowerRegulator is Correct")
            }
            # Check ProcessorPower
            $targetBiosProcessorPower = Get-HPEBIOSProcessorPower -Connection $targetBios
            $targetBiosProcessorPowerPCS = $targetBiosProcessorPower.MinimumProcessorIdlePowerCoreState
            $targetBiosProcessorPowerPPS = $targetBiosProcessorPower.MinimumProcessorIdlePowerPackageState
            if($targetBiosProcessorPowerPCS -ne "C6State" -or $targetBiosProcessorPowerPPS -ne "PackageC3State"){
                Set-HPEBIOSProcessorPower -Connection $targetBios -MinimumProcessorIdlePowerCoreState "C6State" -MinimumProcessorIdlePowerPackageState "PackageC3State"
                write-host -ForegroundColor red $("corrected gen9 targetBiosProcessorPowerPCS $targetBiosProcessorPowerPCS to C6State")
                write-host -ForegroundColor red $("corrected gen9 targetBiosProcessorPowerPPS $targetBiosProcessorPowerPPS to PackageC3State")

            }else{
                write-host -ForegroundColor green $("gen9 targetBiosProcessorPowerPCS $targetBiosProcessorPowerPCS is correct")
                write-host -ForegroundColor green $("gen9 targetBiosProcessorPowerPPS $targetBiosProcessorPowerPPS is correct")
            }
        }

        #Gen10 Check gen10 and correct WorkloadProfile
        if($targetBios.TargetInfo.ServerGeneration -eq "Gen10"){
            $targetBiosWorkloadProfile = (Get-HPEBIOSWorkloadProfile -Connection $targetBios).WorkloadProfile
            if($targetBiosWorkloadProfile -ne "VirtualizationPowerEfficient"){
                Set-HPEBIOSWorkloadProfile -Connection $targetBios -WorkloadProfile "VirtualizationPowerEfficient"
                write-host -ForegroundColor red $("corrected gen10 WorkloadProfile $targetBiosWorkloadProfile to VirtualizationPowerEfficient")
            }else{
                write-host -ForegroundColor green $("gen10 WorkloadProfile $targetBiosWorkloadProfile is Correct")
            }
        }
    # Synergy afhandeling
    }else{
        write-host -ForegroundColor red $("targethost $targetHostsToDo is een Synergy blade. Graag configureren via Server Profile")
    }
}
#endregion Power2023

 

#region Power2023Policy
$targetHostsToDo = $targetHosts
$desiredPowerPolicy = "static"        # Options are: static(=High performance),dynamic (=Balanced),low(=Low power),custom(=Custom)

foreach($targetHostToDo in $targetHostsToDo){
    $targetHostToDo| %{
        $powSys = Get-View $_.ExtensionData.ConfigManager.PowerSystem
        $key = ($powSys.Capability.AvailablePolicy | where {$_.ShortName -eq $desiredPowerPolicy}).Key
        $powSys.ConfigurePowerPolicy($key)
    }
}
#endregion Power2023Policy



#region SynergyTemplatePower

# Retrieve the server profile template
$template = Get-OVServerProfileTemplate -Name testeric
$overriddenSettings = $template.Bios.overriddenSettings

# Check if WorkloadProfile setting has been overridden
    $workloadProfileOverride = $overriddenSettings | Where-Object { $_.id -eq "WorkloadProfile" }
    if ($workloadProfileOverride) {
        # Set value of WorkloadProfile setting
        #optie: Virtualization-MaxPerformance
        #optie: Virtualization-PowerEfficient
        $workloadProfileOverride.value = "Virtualization-PowerEfficient"
        Write-Host -ForegroundColor Green "WorkloadProfile has been set to: $($workloadProfileOverride.value)"
    }else{Write-Host -ForegroundColor Red "WorkloadProfile is not defined in the server profile template."}

# Check if MinProcIdlePkgState setting has been overridden
    $MinProcIdlePkgStateOverride = $overriddenSettings | Where-Object { $_.id -eq "MinProcIdlePkgState" }
    if ($MinProcIdlePkgStateOverride) {
        # Set value of WorkloadProfile setting
        #optie: C6Retention
        #optie: C6NonRetention
        $MinProcIdlePkgStateOverride.value = "C6NonRetention"
        Write-Host -ForegroundColor Green "MinProcIdlePkgState has been set to: $($MinProcIdlePkgStateOverride.value)"
    }else{
        # Override setting doesn't exist, create a new one
        $workloadProfileOverride = New-Object -TypeName HPOneView.PowerShell.Cmdlets.ServerProfileTemplateModule.Api.ServerProfileTemplateOverrides.HPEServerProfileTemplateOverrideSetting
        $workloadProfileOverride.id = "MinProcIdlePkgState"
        $workloadProfileOverride.value = "C6NonRetention"
        $template.Bios.overriddenSettings += $workloadProfileOverride
        Write-Host "WorkloadProfile override setting has been added with value: $($workloadProfileOverride.value)"
    }

# Check if PowerRegulator setting has been overridden
    $PowerRegulatorOverride = $overriddenSettings | Where-Object { $_.id -eq "PowerRegulator" }
    if ($PowerRegulatorOverride) {
        # Set value of WorkloadProfile setting
        #optie: StaticHighPerf
        #optie: PowerRegulatorOverride
        $PowerRegulatorOverride.value = "OsControl"
        Write-Host -ForegroundColor Green "PowerRegulator has been set to: $($PowerRegulatorOverride.value)"
    }else{Write-Host -ForegroundColor Red "PowerRegulator is not defined in the server profile template."}

# Update server profile template
Save-OVServerProfileTemplate  -InputObject $template

#endregion SynergyTemplatePower



