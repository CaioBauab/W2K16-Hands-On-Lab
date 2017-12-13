Start-Transcript -Path C:\Transcript.log

$SecurePassword = Read-Host -Prompt "Enter password" -AsSecureString
$ISO = 'H:\en_windows_server_2016_x64_dvd_9718492.iso'

Function LimpaAmbiente{
    Dismount-DiskImage -StorageType ISO -ImagePath $ISO -Confirm:$false
    Get-VM DC,NanoHost01,NanoHost02 | Stop-VM -TurnOff -Force -Confirm:$false
    Remove-VM -Name DC,NanoHost01,NanoHost02 -Force -Confirm:$false
    Remove-Item C:\Hyper-V -Recurse -Force -Confirm:$false
    Remove-Item H:\Hyper-V -Recurse -Force -Confirm:$false
    Get-NetAdapter | Set-NetIPInterface -Forwarding Disabled
    Remove-NetRoute -InterfaceAlias "vEthernet (BR-SP-PRD)" -DestinationPrefix 192.168.8.0/24 -Confirm:$false
    Remove-NetRoute -InterfaceAlias "vEthernet (Cluster PRD)" -DestinationPrefix 192.168.9.0/24 -Confirm:$false
    Remove-NetRoute -InterfaceAlias "vEthernet (BR-SP-DR)" -DestinationPrefix 192.168.10.0/24 -Confirm:$false
    Remove-NetRoute -InterfaceAlias "vEthernet (Cluster DR)" -DestinationPrefix 192.168.11.0/24 -Confirm:$false
    Remove-NetNat -Name MyNATnetwork -Confirm:$false
    Get-VMSwitch | Remove-VMSwitch -Force -Confirm:$false
}
#LimpaAmbiente

Function PreparaAmbiente{
    Mount-DiskImage -ImagePath $ISO | Out-Null
    Set-Variable -Name "Drive" -Scope Global -Value ((Get-DiskImage -ImagePath $ISO | Get-Volume).DriveLetter)
    Set-VMhost -EnableEnhancedSessionMode $true
    New-VMSwitch -Name 'BR-SP-PRD' -SwitchType Internal
    New-VMSwitch -Name 'Cluster PRD' -SwitchType Internal
    New-VMSwitch -Name 'BR-SP-DR' -SwitchType Internal
    New-VMSwitch -Name 'Cluster DR' -SwitchType Internal
    New-NetIPAddress -IPAddress '192.168.4.1' -PrefixLength 24 -InterfaceIndex (Get-NetAdapter -Name '*BR-SP-PRD*').InterfaceIndex
    New-NetIPAddress -IPAddress '192.168.5.1' -PrefixLength 24 -InterfaceIndex (Get-NetAdapter -Name '*Cluster PRD*').InterfaceIndex
    New-NetIPAddress -IPAddress '192.168.6.1' -PrefixLength 24 -InterfaceIndex (Get-NetAdapter -Name '*BR-SP-DR*').InterfaceIndex
    New-NetIPAddress -IPAddress '192.168.7.1' -PrefixLength 24 -InterfaceIndex (Get-NetAdapter -Name '*Cluster DR*').InterfaceIndex
    New-NetRoute  -DestinationPrefix '192.168.8.0/24' -InterfaceAlias "vEthernet (BR-SP-PRD)"  -AddressFamily IPv4 -NextHop '192.168.4.11'
    New-NetRoute -DestinationPrefix '192.168.9.0/24'  -InterfaceAlias "vEthernet (Cluster PRD)" -AddressFamily IPv4 -NextHop '192.168.5.11'
    New-NetRoute -DestinationPrefix '192.168.10.0/24'  -InterfaceAlias "vEthernet (BR-SP-DR)" -AddressFamily IPv4-NextHop '192.168.6.11'
    New-NetRoute -DestinationPrefix '192.168.11.0/24'  -InterfaceAlias "vEthernet (Cluster DR)" -AddressFamily IPv4 -NextHop '192.168.7.11'
    New-NetNat -Name MyNATnetwork -InternalIPInterfaceAddressPrefix '192.168.4.0/22'
    Get-NetAdapter | Set-NetIPInterface -Forwarding Enabled
    Get-NetAdapter | Disable-NetAdapterBinding -ComponentID ms_tcpip6
    #Import-Module ${Drive}:\NanoServer\NanoServerImageGenerator
}
PreparaAmbiente

Function CriaDC ($Computer,$Volume){
    # Gera VHDX
    . ${Drive}:\NanoServer\NanoServerImageGenerator\Convert-WindowsImage.ps1
    Convert-WindowsImage -SourcePath "${Drive}:\sources\install.wim" -Edition Datacenter -VHDPath "${Volume}:\Hyper-V\$Computer\Virtual Hard Disks\$Computer-C.vhdx" -VHDFormat VHDX -DiskLayout UEFI -RemoteDesktopEnable -BCDinVHD VirtualMachine -UnattendPath H:\DC-Unattend.xml
    
    # Cria, configura e inicia a VM
    New-VM -Name $Computer -Path ${Volume}:\Hyper-V -MemoryStartupBytes 2048MB -Generation 2 -VHDPath "${Volume}:\Hyper-V\$Computer\Virtual Hard Disks\$Computer-C.vhdx" -SwitchName 'BR-SP-PRD'
    Set-VMProcessor –VMName $Computer -Count 2
    Rename-VMNetworkAdapter -VMName $Computer -Name 'Network Adapter' -NewName 'BR-SP-PRD'
    Get-VM -Name DC | Add-VMDvdDrive
    Set-VMDvdDrive -VMName DC -Path $ISO
    Start-VM -Name $Computer
}
CriaDC -Computer "DC" -Volume "H"

Function CriaNano ($Computer,$IPPRD,$IPGW,$Volume,$Enviroment){
    # Gera VHDX. 
    New-NanoServerImage -Edition Datacenter -DeploymentType Guest -MediaPath "${Drive}:\" -BasePath ${Volume}:\Hyper-V\Base -TargetPath "${Volume}:\Hyper-V\$Computer\Virtual Hard Disks\$Computer-C.vhdx" -ComputerName $Computer -Compute -Clustering -Storage -AdministratorPassword $SecurePassword -InterfaceNameOrIndex 'Ethernet' -Ipv4Address $IPPRD -Ipv4SubnetMask 255.255.255.0 -Ipv4Gateway $IPGW -Ipv4Dns 192.168.4.20 -EnableRemoteManagementPort -UnattendPath 'H:\Nano-Unattend.xml'
    # Cria, configura e inicia a VM
    New-VM -Name $Computer -Path ${Volume}:\Hyper-V -MemoryStartupBytes 4352MB -Generation 2 -VHDPath "${Volume}:\Hyper-V\$Computer\Virtual Hard Disks\$Computer-C.vhdx" -SwitchName "BR-SP-$Enviroment"
    Set-VMProcessor -VMName $Computer -ExposeVirtualizationExtensions $true -Count 2
    Set-VMMemory -VMName $Computer -DynamicMemoryEnabled $false
    New-VHD -Path "${Volume}:\Hyper-V\$Computer\Virtual Hard Disks\$Computer-SSD.vhdx" -SizeBytes 10GB -Dynamic
    New-VHD -Path "${Volume}:\Hyper-V\$Computer\Virtual Hard Disks\$Computer-HDD.vhdx" -SizeBytes 60GB -Dynamic
    Add-VMHardDiskDrive -VMName $Computer -ControllerType SCSI -Path "${Volume}:\Hyper-V\$Computer\Virtual Hard Disks\$Computer-SSD.vhdx" -ControllerNumber 0 -ControllerLocation 1
    Add-VMHardDiskDrive -VMName $Computer -ControllerType SCSI -Path "${Volume}:\Hyper-V\$Computer\Virtual Hard Disks\$Computer-HDD.vhdx" -ControllerNumber 0 -ControllerLocation 2
    Enable-VMIntegrationService -Name "Guest Service Interface" -VMName $Computer
    Set-VMFirmware –Vmname $Computer -EnableSecureBoot Off
    Start-VM -Name $Computer
    Start-Sleep -Seconds 20
    ${NICPRD} = (Get-VMNetworkAdapter -VMName $Computer | Where-Object IPAddresses -Match 192.168.).Name
    Rename-VMNetworkAdapter -VMName $Computer -Name ${NICPRD} -NewName "BR-SP-$Enviroment"
    Set-VMNetworkAdapter -VMName $Computer -Name "BR-SP-$Enviroment" -MacAddressSpoofing On
    Add-VMNetworkAdapter -VMName $Computer -Name "Cluster $Enviroment" -SwitchName "Cluster $Enviroment"
    Set-VMNetworkAdapter -VMName $Computer -Name "Cluster $Enviroment" -MacAddressSpoofing On
}
CriaNano -Computer NanoHost01 -IPPRD 192.168.4.11 -IPGW 192.168.4.1 -Volume "H" -Enviroment 'PRD'
CriaNano -Computer NanoHost02 -IPPRD 192.168.6.11 -IPGW 192.168.6.1 -Volume "H" -Enviroment 'DR'
       
Function ConfiguraDC{
    $cred= New-Object System.Management.Automation.PSCredential ("DC\Administrator",$SecurePassword)
    # PowerShell Direct
    Invoke-Command -VMName DC -Credential $cred {param($SecurePassword)
        # Configura rede
        Get-NetAdapter | Rename-NetAdapter -NewName "BR-SP-PRD"
        New-NetIPAddress -InterfaceAlias "BR-SP-PRD" -IPAddress '192.168.4.20' -AddressFamily IPv4 -PrefixLength 24 -DefaultGateway '192.168.4.1'

        # Ajusta itens de BPA
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}" -Name "IsInstalled" -Value 0 -Force
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A8-37EF-4b3f-8CFC-4F3A74704073}" -Name "IsInstalled" -Value 0 -Force
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -Value 00000000 -Force
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Parameters" -Name "Type" -Value "NTP" -Force
        Disable-NetAdapterBinding -Name BR-SP-PRD -ComponentID ms_tcpip6

        # Instala Roles e Features
        Add-WindowsFeature AD-Domain-Services,RSAT-ADDS,RSAT-ADDS-Tools,RSAT-AD-PowerShell,DNS,RSAT-DNS-Server,RSAT-Hyper-V-Tools,Hyper-V-Powershell,RSAT-Clustering,RSAT-Clustering-Powershell,FS-Data-Deduplication
        # Configura DNS
        $DNS = Get-DnsServerSetting -All ; $DNS.ListeningIPAddress = @("192.168.4.20") ; Set-DNSServerSetting -InputObject $DNS
        Set-DnsClientServerAddress -InterfaceAlias "BR-SP-PRD" -ServerAddresses 192.168.4.20
   
        # Instala AD DS
        Install-ADDSForest -CreateDnsDelegation:$false -DatabasePath "C:\Windows\NTDS" -DomainMode "WinThreshold" -DomainName "bauab.local" -DomainNetbiosName "BAUAB" -ForestMode "WinThreshold" -InstallDns:$true -LogPath "C:\Windows\NTDS" -SysvolPath "C:\Windows\SYSVOL" -Force:$true -SafeModeAdministratorPassword $SecurePassword

    } -ArgumentList ($SecurePassword)
    Start-Sleep -Seconds 600
}
ConfiguraDC

$DomainCred = New-Object System.Management.Automation.PSCredential ("Bauab\Administrator",$SecurePassword)

Function ConfiguraDCRoles{
    Invoke-Command -VMName DC -Credential $DomainCred {
        Get-ADReplicationSite -Filter {Name -eq "Default-First-Site-Name"} | Rename-ADObject -NewName "BR-SP-PRD"
        Get-ADReplicationSite -Filter {Name -eq 'BR-SP-PRD'} | Set-ADReplicationSite -Description 'Production Site'
        New-ADReplicationSite -Name BR-SP-DR -Description 'Disaster Recovery Site'
        Get-ADReplicationSiteLink -Filter {Name -eq "DEFAULTIPSITELINK"} | Rename-ADObject -NewName "BR-SP-PRD<>BR-SP-DR"
        Get-ADReplicationSiteLink -Filter {Name -eq "BR-SP-PRD<>BR-SP-DR"} | Set-ADReplicationSiteLink -SitesIncluded @{Add="BR-SP-DR"}
        New-ADReplicationSubnet -Name 192.168.4.0/24 -Description "Production" -Location "São Paulo,Brasil" -Site "BR-SP-PRD"
        New-ADReplicationSubnet -Name 192.168.5.0/24 -Description "Cluster Production" -Location "São Paulo,Brasil" -Site "BR-SP-PRD"
        New-ADReplicationSubnet -Name 192.168.6.0/24 -Description "Disaster Recovery" -Location "São Paulo,Brasil" -Site "BR-SP-DR"
        New-ADReplicationSubnet -Name 192.168.7.0/24 -Description "Cluster Disaster Recovery" -Location "São Paulo,Brasil" -Site "BR-SP-DR"
        New-ADReplicationSubnet -Name 192.168.8.0/24 -Description "Production" -Location "São Paulo,Brasil" -Site "BR-SP-PRD"
        New-ADReplicationSubnet -Name 192.168.9.0/24 -Description "Cluster Production" -Location "São Paulo,Brasil" -Site "BR-SP-PRD"
        New-ADReplicationSubnet -Name 192.168.10.0/24 -Description "Disaster Recovery" -Location "São Paulo,Brasil" -Site "BR-SP-DR"
        New-ADReplicationSubnet -Name 192.168.11.0/24 -Description "Cluster Disaster Recovery" -Location "São Paulo,Brasil" -Site "BR-SP-DR"
        Add-DnsServerPrimaryZone -DynamicUpdate Secure -Name "192.in-addr.arpa" -ReplicationScope Domain
        Set-DnsServerScavenging -ScavengingState $true -ApplyOnAllZones -ScavengingInterval 7.00:00:00
        }
    }
ConfiguraDCRoles

Function ConfiguraNano ($Computer,$IPProd,$IPCluster,$IPClusterClient,$IPClusterOnly,$DestinationPrefix,$NextHop,$Enviroment){
    $cred = New-Object System.Management.Automation.PSCredential ("$Computer\Administrator",$SecurePassword)
    Invoke-Command -VMName DC -Credential $DomainCred -ScriptBlock {param($Computer,$IPProd,$cred)
        # Configura sessão para configurar NanoHosts
        Set-Item WSMan:\localhost\Client\TrustedHosts $Computer -Concatenate -Force
        Add-DnsServerResourceRecordA -IPv4Address $IPProd -Name $Computer -ZoneName bauab.local -AllowUpdateAny -CreatePtr -AgeRecord
        $SessionNano = New-PSSession -ComputerName $Computer -Credential $cred
        Djoin.exe /provision /domain bauab.local /machine $Computer /savefile C:\$Computer.djoin
        Copy-Item C:\$Computer.djoin C:\ -ToSession $SessionNano
        } -ArgumentList ($Computer,$IPProd,$cred)
    Invoke-Command -VMName $Computer -Credential $cred -ScriptBlock {param($Computer,$IPCluster,$IPClusterClient,$IPClusterOnly,$DestinationPrefix,$NextHop,$Enviroment)
        # Dism /online /enable-feature /featurename:dedup-core /all (Deu problema para consumir o vhdx entre os nós. Tive que desativar)
        Set-VMhost -EnableEnhancedSessionMode $true
        New-VMSwitch -Name "Cluster and Client" -SwitchType Internal
        New-VMSwitch -Name "Cluster Only" -SwitchType Internal
        Get-NetAdapter -Name "vEthernet (Cluster and Client)" | New-NetIPAddress -IPAddress $IPClusterClient -AddressFamily IPv4 -PrefixLength 24
        Get-NetAdapter -Name "vEthernet (Cluster Only)" | New-NetIPAddress -IPAddress $IPClusterOnly -AddressFamily IPv4 -PrefixLength 24
        Get-NetAdapter | Set-NetIPInterface -Forwarding Enabled
        Get-NetAdapter -Name ((Get-NetIPAddress | Where-Object {$_.IPAddress -Match '169.' -and $_.AddressState -eq 'Preferred' -and $_.AddressFamily -eq 'IPv4'}).InterfaceAlias) | Rename-NetAdapter -NewName "Cluster $Enviroment" | Set-DnsClient -RegisterThisConnectionsAddress $False
        New-NetIPAddress -InterfaceAlias "Cluster $Enviroment" -IPAddress $IPCluster -AddressFamily IPv4 -PrefixLength 24
        Get-NetAdapter -Name ((Get-NetIPAddress | Where-Object {$_.IPAddress -eq $IPProd -and $_.AddressState -eq 'Preferred'}).InterfaceAlias) | Rename-NetAdapter -NewName "BR-SP-$Enviroment"
        If ($Computer -eq 'NanoHost01'){
            New-NetRoute -DestinationPrefix 192.168.9.0/24 -InterfaceAlias "vEthernet (Cluster Only)" -AddressFamily IPv4 -NextHop 192.168.9.111
            New-NetRoute -DestinationPrefix 192.168.11.0/24 -InterfaceAlias "Cluster PRD" -AddressFamily IPv4 -NextHop 192.168.5.1
            New-NetRoute -DestinationPrefix 192.168.5.0/24 -InterfaceAlias "Cluster PRD" -AddressFamily IPv4 -NextHop 192.168.5.1
        }
        Else {
            New-NetRoute -DestinationPrefix 192.168.11.0/24 -InterfaceAlias "vEthernet (Cluster Only)" -AddressFamily IPv4 -NextHop 192.168.11.111
            New-NetRoute -DestinationPrefix 192.168.7.0/24 -InterfaceAlias "Cluster DR" -AddressFamily IPv4 -NextHop 192.168.7.1
            New-NetRoute -DestinationPrefix 192.168.9.0/24 -InterfaceAlias "Cluster DR" -AddressFamily IPv4 -NextHop 192.168.7.1
        }

        # Ajusta itens de BPA
        Set-NetFirewallProfile -All -Enabled False
        Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -Name fDenyTSConnections -Value 0 -Force
        Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -Value 00000000 -Force
        Set-TimeZone "E. South America Standard Time"
        Disable-NetAdapterBinding -ComponentID ms_tcpip6 -Name *
        # Adiciona ao domínio bauab.local
        Djoin.exe /RequestODJ /loadfile C:\$Computer.djoin /windowspath c:\windows /localos
        } -ArgumentList ($Computer,$IPCluster,$IPClusterClient,$IPClusterOnly,$DestinationPrefix,$NextHop,$Enviroment)
    Stop-VM $Computer ; Start-VM $Computer
    }
ConfiguraNano -Computer "NanoHost01" -IPProd 192.168.4.11 -IPCluster 192.168.5.11 -IPClusterClient 192.168.8.1 -IPClusterOnly 192.168.9.1 -DestinationPrefix 192.168.9.0/24 -NextHop 192.168.9.111 -Enviroment 'PRD'
ConfiguraNano -Computer "NanoHost02" -IPProd 192.168.6.11 -IPCluster 192.168.7.11 -IPClusterClient 192.168.10.1 -IPClusterOnly 192.168.11.1 -DestinationPrefix 192.168.10.0/24 -NextHop 192.168.10.111 -Enviroment 'DR'
Start-Sleep -Seconds 30

# Criação do Failover Cluster com Storage Pool Direct entre os NanoHosts
Invoke-Command -VMName DC -Credential $DomainCred {
    # Seguir http://www.int2skynet.net/2015/11/22/deploying-a-nested-hyper-converged-hyper-v-cluster-with-powershell-and-nano-server-2016-technical-preview-4/
    # Testa e cria cluster
    #Test-Cluster –Node NanoHost01,NanoHost02 –Include "Storage Spaces Direct","Inventory","Network","System Configuration" -ReportName C:\NanoCluster
    New-Cluster -Name NanoCluster -Node NanoHost01,NanoHost02 -StaticAddress 192.168.4.10,192.168.6.10 -NoStorage
    New-Item C:\Quorum -ItemType Directory
    $acl = Get-Acl -Path C:\Quorum
    $perm = "bauab\NanoCluster$", 'Read,Modify', 'ContainerInherit, ObjectInherit', 'None', 'Allow' 
    $rule = New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule -ArgumentList $perm
    $acl.SetAccessRule($rule) 
    $acl | Set-Acl -Path C:\Quorum
    New-SmbShare -Name "Quorum" -Path "C:\Quorum" -FullAccess "bauab\NanoCluster$"
    Start-Sleep 60
    Set-ClusterQuorum -FileShareWitness \\dc\Quorum -Cluster NanoCluster.bauab.local
    (Get-ClusterNetwork -Cluster NanoCluster.bauab.local | Where-Object {$_.Address -eq "192.168.4.0"}).Name = "BR-SP-PRD"
    (Get-ClusterNetwork -Cluster NanoCluster.bauab.local | Where-Object {$_.Address -eq "192.168.5.0"}).Name = "Cluster PRD"
    (Get-ClusterNetwork -Cluster NanoCluster.bauab.local | Where-Object {$_.Address -eq "192.168.6.0"}).Name = "BR-SP-DR"
    (Get-ClusterNetwork -Cluster NanoCluster.bauab.local | Where-Object {$_.Address -eq "192.168.7.0"}).Name = "Cluster DR"
    (Get-ClusterNetwork -Cluster NanoCluster.bauab.local | Where-Object {$_.Address -eq "192.168.8.0"}).Name = "Cluster and Client"
    (Get-ClusterNetwork -Cluster NanoCluster.bauab.local | Where-Object {$_.Address -eq "192.168.9.0"}).Name = "Cluster Only"
    (Get-ClusterNetwork -Cluster NanoCluster.bauab.local | Where-Object {$_.Address -eq "192.168.10.0"}).Name = "Cluster and Client DR"
    (Get-ClusterNetwork -Cluster NanoCluster.bauab.local | Where-Object {$_.Address -eq "192.168.11.0"}).Name = "Cluster Only DR"
    #Ajusta ordem e quais placas atuarão no live migration

    # Habilita Storage Pool Direct com os Nanos, criando Storage Pool direto no cluster
    $ClusterSession = New-CimSession -ComputerName NanoCluster.bauab.local
    Enable-ClusterStorageSpacesDirect –CimSession $ClusterSession -CacheState Disabled -SkipEligibilityChecks -confirm:$false

    # Ajusta SSD e HDD
    Get-PhysicalDisk -CimSession $ClusterSession | Where Size -EQ 10GB | Set-PhysicalDisk -CimSession $ClusterSession -MediaType SSD
    Get-PhysicalDisk -CimSession $ClusterSession | Where Size -EQ 60GB | Set-PhysicalDisk -CimSession $ClusterSession -MediaType HDD
    Get-PhysicalDisk -CimSession $ClusterSession | select Size,mediatype

    # Cria Storage Tiers
    Get-StoragePool -CimSession $ClusterSession -FriendlyName "S2D*" | New-StorageTier –FriendlyName Performance –MediaType SSD
    Get-StorageTier -CimSession $ClusterSession | FT FriendlyName,Size
    Get-StoragePool -CimSession $ClusterSession -FriendlyName "S2D*" | FL Size, AllocatedSize
    Get-StorageTierSupportedSize -CimSession $ClusterSession Performance | FT -AutoSize
    Get-StorageTierSupportedSize -CimSession $ClusterSession Capacity | FT -AutoSize

    # Cria disco e volume ReFS CSV com tiers SSD e HDD e habilita Deduplication
    $Volume = New-Volume -CimSession $ClusterSession -StoragePoolFriendlyName "S2D*" -FriendlyName VMs -FileSystem CSVFS_NTFS -StorageTierFriendlyNames Performance,Capacity -StorageTierSizes 7GB,56GB -ResiliencySettingName Mirror -WriteCacheSize 1GB -ProvisioningType Fixed # Testar Thin
    # Enable-DedupVolume -CimSession $ClusterSession -Volume $Volume.Path -UsageType HyperV (Deu problema para consumir o vhdx entre os nós. Tive que desativar)
}

# Deploy 2 vms Windows 2016 Datacenter Nano: Failover, Storage, Deduplication
Function CriaGuest ($Computer,$Enviroment){
    # Gera VHDX Windows Server 2016 Datacenter Full
    $NanoHost = "NanoHost0$($Computer.Substring($Computer.Length -1))"
    . ${Drive}:\NanoServer\NanoServerImageGenerator\Convert-WindowsImage.ps1
    #Convert-WindowsImage -SourcePath "${Drive}:\sources\install.wim" -Edition Datacenter -VHDPath "H:\Hyper-V\$Computer-C.vhdx" -VHDFormat VHDX -DiskLayout UEFI -RemoteDesktopEnable -BCDinVHD VirtualMachine -UnattendPath "H:\Guest0$($Computer.Substring($Computer.Length -1))-Unattend.xml"
    Copy-VMFile -FileSource Host -SourcePath "H:\Hyper-V\$Computer-C.vhdx" -Name NanoHost01 -DestinationPath "C:\ClusterStorage\Volume1\Hyper-V\$Computer\Virtual Hard Disks\$Computer-C.vhdx" -CreateFullPath
    Invoke-Command -VMName DC -Credential $DomainCred {Param($Computer,$NanoHost,$Enviroment)
        #New-Item "\\$NanoHost\C$\ClusterStorage\Volume1\Hyper-V\$Computer\Virtual Hard Disks" -ItemType Directory

        
        #Convert-WindowsImage -SourcePath "D:\sources\install.wim" -Edition Datacenter -VHDPath "\\$NanoHost\C$\ClusterStorage\Volume1\Hyper-V\$Computer\Virtual Hard Disks\$Computer-C.vhdx" -VHDFormat VHDX -DiskLayout UEFI -RemoteDesktopEnable -BCDinVHD VirtualMachine -UnattendPath "\\$NanoHost\C$\ClusterStorage\Volume1\Hyper-V\$Computer\Guest0$($Computer.Substring($Computer.Length -1))-Unattend.xml"
        # Cria e configura VM em 1 NanoHost
        New-VM -ComputerName $NanoHost -Name $Computer -Path C:\ClusterStorage\Volume1\Hyper-V -MemoryStartupBytes 1792MB -Generation 2 -VHDPath "C:\ClusterStorage\Volume1\Hyper-V\$Computer\Virtual Hard Disks\$Computer-C.vhdx" -SwitchName "Cluster and Client"
        Set-VMProcessor -ComputerName $NanoHost -VMName $Computer -Count 2
        Set-VMMemory -ComputerName $NanoHost -VMName $Computer -DynamicMemoryEnabled $false
        Rename-VMNetworkAdapter -ComputerName $NanoHost -VMName $Computer -Name "Network Adapter" -NewName "BR-SP-$Enviroment"

        #Adicionar 2 discos Thin para storage réplica
        New-VHD -ComputerName $NanoHost -Path "C:\ClusterStorage\Volume1\Hyper-V\$Computer\Virtual Hard Disks\$Computer-Log.vhdx" -SizeBytes 9GB -Dynamic
        New-VHD -ComputerName $NanoHost -Path "C:\ClusterStorage\Volume1\Hyper-V\$Computer\Virtual Hard Disks\$Computer-Data.vhdx" -SizeBytes 10GB -Dynamic
        Add-VMHardDiskDrive -ComputerName $NanoHost -VMName $Computer -ControllerType SCSI -Path "C:\ClusterStorage\Volume1\Hyper-V\$Computer\Virtual Hard Disks\$Computer-Log.vhdx" -ControllerNumber 0 -ControllerLocation 1
        Add-VMHardDiskDrive -ComputerName $NanoHost -VMName $Computer -ControllerType SCSI -Path "C:\ClusterStorage\Volume1\Hyper-V\$Computer\Virtual Hard Disks\$Computer-Data.vhdx" -ControllerNumber 0 -ControllerLocation 2
        
        # Adiciona a VM no Cluster e inicia
        Add-ClusterVirtualMachineRole -Cluster NanoCluster -VirtualMachine $Computer
        Set-ClusterOwnerNode -Cluster NanoCluster -Group $Computer -Owners $NanoHost
        #Start-VM -ComputerName NanoCluster -Name $Computer
                
    } -ArgumentList($Computer,$NanoHost,$Enviroment)
}
CriaGuest -Computer "Guest01" -Enviroment 'PRD'
CriaGuest -Computer "Guest02" -Enviroment 'DR'
Start-Sleep -Seconds 600

Function ConfiguraGuest($NanoHost,$Guest,$IPPRD,$IPClus,$IPGW,$Enviroment){
    $credGuest= New-Object System.Management.Automation.PSCredential ("$Guest\Administrator",$SecurePassword)
    Invoke-Command -VMName $NanoHost -Credential $DomainCred {Param($Guest,$IPPRD,$IPClus,$IPGW,$Enviroment,$credGuest)
        While ((Get-VMNetworkAdapter -VMName $Guest | Where-Object IPAddresses -Match 169.) -eq $null){Start-Sleep 5}
        Invoke-AsWorkflow -VMName $Guest -Credential $credGuest {Param($IPPRD,$IPGW,$Enviroment)
            # Configura rede Client and Cluster
            Get-NetAdapter | Rename-NetAdapter -NewName "BR-SP-$Enviroment"
            New-NetIPAddress -InterfaceAlias "BR-SP-$Enviroment" -IPAddress $IPPRD -AddressFamily IPv4 -PrefixLength 24 -DefaultGateway $IPGW
            Set-DnsClientServerAddress -InterfaceAlias "BR-SP-$Enviroment" -ServerAddresses 192.168.4.20
            # Ajusta itens de BPA
            $AdminKey = "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}"
            $UserKey = "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A8-37EF-4b3f-8CFC-4F3A74704073}"
            Set-ItemProperty -Path $AdminKey -Name "IsInstalled" -Value 0 -Force
            Set-ItemProperty -Path $UserKey -Name "IsInstalled" -Value 0 -Force
            Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -Value 00000000 -Force
            # Instala Roles e Features
            Add-WindowsFeature Failover-Clustering,FS-Data-Deduplication,Storage-Replica,FS-FileServer -IncludeManagementTools -Restart
        } -ArgumentList($IPPRD,$IPGW,$Enviroment)
        #Stop-VM $Guest ; Start-VM $Guest
        #Start-Sleep -Seconds 600
        While ((Get-VM -VMName $Guest).Uptime.Minutes -gt 1) {Start-Sleep 5}
        #While ((Get-VMNetworkAdapter -VMName $Guest | Where-Object IPAddresses -Match 192.) -eq $null){Start-Sleep 5}
        Add-VMNetworkAdapter -VMName $Guest -Name "Cluster $Enviroment" -SwitchName "Cluster Only"
        While ((Get-VMNetworkAdapter -VMName $Guest | Where-Object IPAddresses -Match 169.) -eq $null){Start-Sleep 5}
        Invoke-Command -VMName $Guest -Credential $credGuest {Param($Guest,$IPClus,$Enviroment)
            # Configura rede cluster
            Get-NetAdapter -Name ((Get-NetIPAddress | Where-Object {$_.IPAddress -Match '169.' -and $_.AddressState -eq 'Preferred' -and $_.AddressFamily -eq 'IPv4'}).InterfaceAlias) | Rename-NetAdapter -NewName "Cluster $Enviroment"
            Get-NetAdapter -Name "Cluster $Enviroment" | Set-DnsClient -RegisterThisConnectionsAddress $False
            New-NetIPAddress -InterfaceAlias "Cluster $Enviroment" -IPAddress $IPClus -AddressFamily IPv4 -PrefixLength 24
            Disable-NetAdapterBinding -Name * -ComponentID ms_tcpip6
            If ($Guest -eq 'Guest01'){
                New-NetRoute -DestinationPrefix 192.168.9.0/24 -InterfaceAlias "Cluster PRD" -AddressFamily IPv4 -NextHop 192.168.9.1
                New-NetRoute -DestinationPrefix 192.168.11.0/24 -InterfaceAlias "Cluster PRD" -AddressFamily IPv4 -NextHop 192.168.9.1
                }
            Else{
                New-NetRoute -DestinationPrefix 192.168.11.0/24 -InterfaceAlias "Cluster DR" -AddressFamily IPv4 -NextHop 192.168.11.1
                New-NetRoute -DestinationPrefix 192.168.9.0/24 -InterfaceAlias "Cluster DR" -AddressFamily IPv4 -NextHop 192.168.11.1
                }
            #Inicializa o disco, cria partição e volume como ReFS e ativa dedup no volume de dados (ver se dá em ReFS agora no 2016)
            Get-Disk | Where size -eq 10GB | Initialize-Disk -PartitionStyle GPT -PassThru | New-Partition -DriveLetter D  -UseMaximumSize | Format-Volume -FileSystem NTFS -NewFileSystemLabel "Dados" -Confirm:$false
            Get-Disk | Where size -eq 9GB | Initialize-Disk -PartitionStyle GPT -PassThru | New-Partition -DriveLetter L -UseMaximumSize | Format-Volume -FileSystem NTFS -NewFileSystemLabel "Log" -Confirm:$false
            Get-Volume | Where size -LE 10GB | Enable-DedupVolume -UsageType Default
        } -ArgumentList($Guest,$IPClus,$Enviroment)
    } -ArgumentList($Guest,$IPPRD,$IPClus,$IPGW,$Enviroment,$credGuest)
    Invoke-Command -VMName DC -Credential $DomainCred {param($Guest,$IPPRD,$credGuest)
        # Configura sessão para configurar Guest
        Set-Item WSMan:\localhost\Client\TrustedHosts $Guest -Concatenate -Force
        Add-DnsServerResourceRecordA -IPv4Address $IPPRD -Name $Guest -ZoneName bauab.local -AllowUpdateAny -CreatePtr -AgeRecord
        If (Test-Connection -ComputerName $Guest -Quiet)
            {
            $SessionGuest = New-PSSession -ComputerName $Guest -Credential $credGuest
            Djoin.exe /provision /domain bauab.local /machine $Guest /savefile C:\$Guest.djoin
            Copy-Item C:\$Guest.djoin C:\ -ToSession $SessionGuest
            }
        } -ArgumentList ($Guest,$IPPRD,$credGuest)
    Invoke-Command -VMName $NanoHost -Credential $DomainCred {Param($Guest,$credGuest)
        While ((Get-VMNetworkAdapter -VMName $Guest | Where-Object IPAddresses -Match 192.) -eq $null){Start-Sleep 5}
        Invoke-Command -VMName $Guest -Credential $credGuest {Param($Guest)
            # Adiciona ao domínio bauab.local
            Djoin.exe /RequestODJ /loadfile C:\$Guest.djoin /windowspath c:\windows /localos
        } -ArgumentList($Guest)
        Stop-VM $Guest ; Start-VM $Guest
    } -ArgumentList($Guest,$credGuest)
}
ConfiguraGuest -NanoHost NanoHost01 -Guest Guest01 -IPPRD 192.168.8.111 -IPClus 192.168.9.111 -IPGW 192.168.8.1 -Enviroment PRD
ConfiguraGuest -NanoHost NanoHost02 -Guest Guest02 -IPPRD 192.168.10.111 -IPClus 192.168.11.111 -IPGW 192.168.10.1 -Enviroment DR
#Start-Sleep 300

# https://docs.microsoft.com/en-us/windows-server/storage/storage-replica/stretch-cluster-replication-using-shared-storage
Function ConfiguraGuestCluster{
    Invoke-Command -VMName NanoHost01 -Credential $DomainCred -ScriptBlock {Param($DomainCred)
        While ((Get-VMNetworkAdapter -VMName Guest01 | Where-Object IPAddresses -Match 192.) -eq $null){Start-Sleep 5}
        While ((Get-VMNetworkAdapter -VMName Guest02 | Where-Object IPAddresses -Match 192.) -eq $null){Start-Sleep 5}
        Invoke-Command -VMName Guest01 -Credential $DomainCred -ScriptBlock {
            # Cria Stretch Cluster
            #Test-Cluster –Node Guest01,Guest02 –Include "Inventory","Network","System Configuration","Storage"  -ReportName C:\GuestCluster
            New-Cluster GuestCluster –Node Guest01,Guest02 –StaticAddress 192.168.8.100,192.168.10.100 -NoStorage
        }
    } -ArgumentList($DomainCred)
    #Start-Sleep 120
    
    If (Test-Connection -ComputerName GuestCluster -Quiet)
        {
        Invoke-Command -VMName DC -Credential $DomainCred -ScriptBlock {
            # Cria Share para GuestCluster
            New-Item C:\GuestQuorum -ItemType Directory
            $acl = Get-Acl -Path C:\GuestQuorum
            $perm = "bauab\GuestCluster$", 'Read,Modify', 'ContainerInherit, ObjectInherit', 'None', 'Allow' 
            $rule = New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule -ArgumentList $perm
            $acl.SetAccessRule($rule) 
            $acl | Set-Acl -Path C:\GuestQuorum
            New-SmbShare -Name "GuestQuorum" -Path "C:\GuestQuorum" -FullAccess "bauab\GuestCluster$"
        }
        Invoke-Command -VMName NanoHost01 -Credential $DomainCred -ScriptBlock {Param($DomainCred)
            Invoke-Command -VMName Guest01 -Credential $DomainCred -ScriptBlock {
                Set-ClusterQuorum -FileShareWitness \\dc\GuestQuorum -Cluster GuestCluster.bauab.local
                (Get-ClusterNetwork -Cluster GuestCluster | Where-Object {$_.Address -eq "192.168.8.0"}).Name = "BR-SP-PRD"
                (Get-ClusterNetwork -Cluster GuestCluster | Where-Object {$_.Address -eq "192.168.9.0"}).Name = "Cluster PRD"
                (Get-ClusterNetwork -Cluster GuestCluster | Where-Object {$_.Address -eq "192.168.10.0"}).Name = "BR-SP-DR"
                (Get-ClusterNetwork -Cluster GuestCluster | Where-Object {$_.Address -eq "192.168.11.0"}).Name = "Cluster DR"
                Get-ClusterResource -Cluster GuestCluster -Name "Cluster Name" | Set-ClusterParameter HostRecordTTL 300
      
                # Configure stretch cluster site awareness
                New-ClusterFaultDomain -Name BR-SP-PRD -Type Site -Description “Production" -Location “BR-SP-PRD"  
                New-ClusterFaultDomain -Name BR-SP-DR -Type Site -Description “DR" -Location “BR-SP-DR"  
                Set-ClusterFaultDomain -Name Guest01 -Parent BR-SP-PRD
                Set-ClusterFaultDomain -Name Guest02 -Parent BR-SP-DR
                (Get-Cluster).PreferredSite=“BR-SP-PRD“
                Get-ClusterAvailableDisk -All -Cluster GuestCluster | Add-ClusterDisk

                # Cria role de File Share
                Add-ClusterFileServerRole -Cluster GuestCluster -Name FS -Storage "Cluster Disk 3" -StaticAddress 192.168.8.101,192.168.10.101
                MD D:\Shares\Public
                $acl = Get-Acl -Path D:\Shares\Public
                $perm = "bauab\Administrator", 'Read,Modify', 'ContainerInherit, ObjectInherit', 'None', 'Allow' 
                $rule = New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule -ArgumentList $perm
                $acl.SetAccessRule($rule) 
                $acl | Set-Acl -Path D:\Shares\Public
                New-SmbShare -Name Public -Path D:\Shares\Public -ContinuouslyAvailable $false -FullAccess "bauab\Administrator"
                Get-ClusterResource -Cluster GuestCluster -Name FS | Set-ClusterParameter HostRecordTTL 300
          
                # Habilita Storage Replica
                #Test-SRTopology -SourceComputerName Guest01.bauab.local -SourceVolumeName D: -SourceLogVolumeName L: -DestinationComputerName Guest02.bauab.local -DestinationVolumeName D: -DestinationLogVolumeName L: -DurationInMinutes 3 -ResultPath c:\
                New-SRPartnership -SourceComputerName Guest01.bauab.local -SourceRGName rg01 -SourceVolumeName D: -SourceLogVolumeName L: -DestinationComputerName Guest02.bauab.local -DestinationRGName rg02 -DestinationVolumeName D: -DestinationLogVolumeName L:
            }
        } -ArgumentList($DomainCred)
    }
}
ConfiguraGuestCluster

# Aplica patches em todas usando role nos clusters
Stop-Transcript