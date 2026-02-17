<#
.SYNOPSIS
                Use this script to check if a device is ESS-capable.
.DESCRIPTION
                This script checks if a device is ESS-capable. It checks USB host controllers and cameras.
.EXAMPLE
                Run it manually on a local device 
                !!!!  much more testing is required !!!!  if you intend to use it a an Intune detection script to check if a device is ESS-capable
.NOTES
                Nicklas Ahlberg:  initial development and explanaition         https://www.rockenroll.tech/2025/01/21/windows-hello-enhanced-sign-in-security/
                Nicklas Ahlberg:  basic scripts from                           https://github.com/NicklasAhlberg/Intune/tree/main/Remediations/WHfB

                saecloud.ch       hardware detection queries                   https://saecloud.ch/remediation-scripts/detect-whfb-hardware-devices/

                Oliver D.:        2026-Feb-12: several steps re-used and several improvents added
#>

function Check-DeviceCapabilities__CM_DEVCAP_SECUREDEVICE_for_WHfB_ESS 
    {
    param ( [string]$deviceName , [Switch]$MyDebug)
    
    [Flags()]
    enum DeviceCapabilities 
        {
          NOTSET             = 0x0000
          LOCKSUPPORTED      = 0x0001
          EJECTSUPPORTED     = 0x0002
          REMOVABLE          = 0x0004   #   4
          DOCKDEVICE         = 0x0008
          UNIQUEID           = 0x0010   #  16
          SILENTINSTALL      = 0x0020   #  32
          RAWDEVICEOK        = 0x0040   #  64
          SURPRISEREMOVALOK  = 0x0080   # 128
          HARDWAREDISABLED   = 0x0100
          NONDYNAMIC         = 0x0200
          SECUREDEVICE       = 0x0400
        }
 
    # x0094    9*16 + 4
    $DeviceObjects = @()
    $DeviceObject = $Null
    $devices = Get-PnpDevice | Where-Object { $_.FriendlyName -like "*$deviceName*" -and $_.Status -eq 'OK'}
    if ($devices) 
        {
        ForEach ( $device in $devices )
            {
            Write-Host "Check-DeviceCapabilities() '$deviceName' - '$($device.InstanceId)' - " -NoNewline
            $DevProperties = Get-PnpDeviceProperty -InstanceId $($device.InstanceId)
            if ( ($DevProperties | Where { $_.KeyName -eq "DEVPKEY_Device_Service" }).Data -eq 'usbaudio'  -or `
                 ($DevProperties | Where { $_.KeyName -eq "DEVPKEY_Device_Class" }).Data   -eq 'AudioEndpoint' )
                {
                # skip this '$device.InstanceId' because it is an AUDIO device - e.g. 'Microphone' 
                 Write-Host "Check-DeviceCapabilities() SKIPPED`r`nCheck-DeviceCapabilities() --- because USBAUDIO/AudioEndpoint (e.g. microphone in camera  or  audio-software)`r`n" -ForegroundColor Red
                }
            else
                {
                $DeviceHashtable = @{     InstanceId     = $device.InstanceId  ;      deviceName = $deviceName  }
                
                $DeviceObject = New-Object -TypeName PSObject -Property $DeviceHashtable
                $DeviceObject | Add-Member -MemberType NoteProperty -Name 'Capabilities_INT'               -Value 0
                $DeviceObject | Add-Member -MemberType NoteProperty -Name 'Capabilities_STRING'            -Value $Null
                $DeviceObject | Add-Member -MemberType NoteProperty -Name 'Capabilities_SECUREDEVICE'      -Value $False
                $DeviceObject | Add-Member -MemberType NoteProperty -Name 'Capabilities_FPR_Reg_Secure'        -Value "registry, if FingerPrint Reader"
                $DeviceObject | Add-Member -MemberType NoteProperty -Name 'Capabilities_FPR_Reg_ConfigFolders' -Value "registry, if FingerPrint Reader"
                $DeviceObject | Add-Member -MemberType NoteProperty -Name 'Capabilities_FPR_Reg_Summary'       -Value "registry, if FingerPrint Reader"
                
                $DeviceObject | Add-Member -MemberType NoteProperty -Name 'Class'           -Value ($DevProperties | Where { $_.KeyName -eq "DEVPKEY_Device_Class" }).Data           #  = 'Biometric' 
                $DeviceObject | Add-Member -MemberType NoteProperty -Name 'Service'         -Value ($DevProperties | Where { $_.KeyName -eq "DEVPKEY_Device_Service" }).Data         # 
                $DeviceObject | Add-Member -MemberType NoteProperty -Name 'Parent'          -Value ($DevProperties | Where { $_.KeyName -eq "DEVPKEY_Device_Parent" }).Data          #  = 'USB\ROOT_HUB30\4&de9ba18&0&0'
                $DeviceObject | Add-Member -MemberType NoteProperty -Name 'Driver'          -Value ($DevProperties | Where { $_.KeyName -eq "DEVPKEY_Device_ConfigurationId" }).Data #  = 'oem28.inf:USB\VID_27C6&PID_634C,MyDevice_Install.NT'
                $DeviceObject | Add-Member -MemberType NoteProperty -Name 'InstallDate'     -Value ($DevProperties | Where { $_.KeyName -eq "DEVPKEY_Device_InstallDate" }).Data     #  = 'Freitag, 13. Februar 2026 14:05:06'
                $DeviceObject | Add-Member -MemberType NoteProperty -Name 'Provider'        -Value ($DevProperties | Where { $_.KeyName -eq "DEVPKEY_Device_DriverProvider" }).Data  #  = 'Goodix'
                $DeviceObject | Add-Member -MemberType NoteProperty -Name 'Description'     -Value ($DevProperties | Where { $_.KeyName -eq "DEVPKEY_Device_DriverDesc" }).Data      #  = 'Goodix MOC Fingerprint'
                $DeviceObject | Add-Member -MemberType NoteProperty -Name 'Version'         -Value ($DevProperties | Where { $_.KeyName -eq "DEVPKEY_Device_DriverVersion" }).Data   #  = '3.4.340.330'
                $DeviceObject | Add-Member -MemberType NoteProperty -Name 'Driver-Date'     -Value ($DevProperties | Where { $_.KeyName -eq "DEVPKEY_Device_DriverDate" }).Data      #  = 'Sonntag, 10. Dezember 2023 01:00:00'
                $DeviceObject | Add-Member -MemberType NoteProperty -Name 'ESS_Capable__REG_and_DEVCAP_SECUREDEVICE'     -Value "not rated until now"        
 
                [UInt32]$deviceCapabilities =  ($DevProperties | Where { $_.KeyName -eq "DEVPKEY_Device_Capabilities" }).Data

                if ( $deviceCapabilities )
                    {
                    $arr = [bitconverter]::GetBytes($deviceCapabilities)
                    $DeviceObject.Capabilities_INT = [bitconverter]::ToInt32($arr,0)
                    
                    [DeviceCapabilities]$DevCap =  (Get-PnpDeviceProperty -InstanceId $($device.InstanceId) -KeyName DEVPKEY_Device_Capabilities).Data -as [DeviceCapabilities]
                    Write-Host $DevCap   # will get appended at last "Write-Host" line - see above
                    $DeviceObject.Capabilities_STRING = $DevCap 
                    if ($deviceCapabilities.Data -band 0x0400) 
                        {
                        $DeviceObject.Capabilities_SECUREDEVICE = $True
                        }
                   }
                else
                    {
                    Write-Host
                    Write-Host "Check-DeviceCapabilities() '$deviceName' - 'deviceCapabilities' are NULL."
                    }
                } # END     NOT ($DevProperties | Where { $_.KeyName -eq "DEVPKEY_Device_Service" }).Data -eq 'usbaudio'
            $DeviceObjects += $DeviceObject
            } # END   ForEach ( $device in $devices )
        }
    else 
        {
        Write-Output "Check-DeviceCapabilities() Device '$deviceName' not found."
        }
    return $DeviceObjects
    }



#########################################################################
#
# collect device information
#
#########################################################################

Clear-Host
$AllDeviceObjects = @()

$MyDebug = $True

#   !   !   !   !   !   !   !   !   !   !   !   !
# NOTE :    cctk --fingerprintreader=Enabled    => REBOOT required
#          and up to    50 min after the REBOOT   the ESS service may raise the first Events
#
# Get Fingerprint readers  (exclude Hello Face devices)
$fingerprintDevices = @()
$fingerprintDevices = Get-PnpDevice -Class Biometric -Status OK -ErrorAction SilentlyContinue `
    | Where-Object { $_.FriendlyName -notmatch '(?i)(IR\s?Camera|RealSense|Depth\sCamera|Infrared\sCamera|Windows Hello|Facial Recognition|IR)' }
#collect and sort fingerprint names
$fpNames = $fingerprintDevices | Select-Object -ExpandProperty FriendlyName | Sort-Object
Write-Host "------------------------------------"
if ($fpNames) 
    {
    Write-Output "following 'Fingerprint Reader(s)' are detected:    '$($fpNames -join "', '")'"
    foreach ($FingerprintDevice in $fingerprintDevices) { 
        
        $DeviceObject = Check-DeviceCapabilities__CM_DEVCAP_SECUREDEVICE_for_WHfB_ESS -deviceName $FingerprintDevice.FriendlyName }

        $DeviceObject.Capabilities_FPR_Reg_Secure        = $False
        $DeviceObject.Capabilities_FPR_REG_ConfigFolders = $False
        $DeviceObject.Capabilities_FPR_Reg_Summary       = $False

        #  $FPR_InstanceID = (Get-PnpDevice -Class Biometric -Status OK -ErrorAction SilentlyContinue  | Where { $_.FriendlyName -like "*Fingerprint*" }).InstanceId
        #  $FPR_InstanceID                                # USB\VID_27C6&PID_634C\UID8C267D71_XXXX_MOC_B0
        #
        #  Path from RegEdit
        #  HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\USB\VID_27C6&PID_634C\UID8C267D71_XXXX_MOC_B0\Device Parameters\WinBio\Configurations
        
        # ########################################################################################
        # There should be a registry key listed named 'SecureFingerprint' with a data value of 1. If it doesn't exist, the device isn't secure-capable.
                
        $RegPath = "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\" + $($DeviceObject.InstanceId) + "\Device Parameters\WinBio\Configurations"
        if ( $MyDebug ) { Write-Host "`r`n`r`nRegKey '$RegPath'  -  'SecureFingerprint' should be '1'" }
        
        #
        #   Because of the '&' ( as part of $($DeviceObject.InstanceId) )  in the RegPath   use '....Microsoft.PowerShell.Core\Registry:...'
        #
        # Get-Item -Path "Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\USB\VID_27C6&PID_634C\UID8C267D71_XXXX_MOC_B0\Device Parameters\WinBio\Configurations"

        $RegPathExists = Get-Item -Path ("Microsoft.PowerShell.Core\Registry::" + $RegPath)  -ErrorAction SilentlyContinue
        if ( $RegPathExists )
            {
            if ( $MyDebug ) { Write-Host "RegPath exists " }
            #
            #               Name                           Property                                                                                                                                                         
            #               ----                           --------                                                                                                                                                         
            #               Configurations                 DefaultConfiguration       : 0                                                                                                                                   
            #                                              SecureFingerprint          : 1                                                                                                                                   
            #                                              VirtualSecureConfiguration : 1      
            $RegKeyExists = Get-ItemProperty -Path ("Microsoft.PowerShell.Core\Registry::" + $RegPath) -ErrorAction SilentlyContinue | Where { $_.Property -eq 'SecureFingerprint' }
            if ( $RegKeyExists )
                {
                if ( $MyDebug ) { Write-Host "RegKey  exists" }
                $RegValue = Get-ItemPropertyValue -Path ("Microsoft.PowerShell.Core\Registry::" + $RegPath) -Name SecureFingerprint  -ErrorAction SilentlyContinue
                if ( $RegValue )
                    {
                    if ( $RegValue -eq 1 ) { $DeviceObject.Capabilities_FPR_Reg_Secure = $True }
                    }
                }
            }
        Write-Output "Result from Registry:  Device '$($DeviceObject.deviceName)' - ESS capability registry query part 1o2: ('SecureFingerprint' eq 1) = $($DeviceObject.Capabilities_FPR_Reg_Secure)`r`n"
        
        # ########################################################################################
        # Configurations should also have two folders beneath it: one labeled 0 and one labeled 1. 
        if ( $MyDebug ) { Write-Host "RegKey '$RegPath'  -  RegSubFolders '0' and '1' have to exists" }
        if ( $DeviceObject.Capabilities_FPR_Reg_Secure -eq $false )
            {
            if ( $MyDebug ) { Write-Host "SKIPPED, because condition ""'SecureFingerprint' eq 1"" is not fullfilled" -ForegroundColor yellow }
            }
        else
            {
            # If there's only one folder and not two, the device isn't secure-capable.
            $RegPath = "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\" + $($DeviceObject.InstanceId) + "\Device Parameters\WinBio\Configurations\0"
            if ( $MyDebug ) { Write-Host "RegKey - RegSubFolders '0' - query existence" }
            $ConfigurationFolder0_exists = Get-Item -Path ("Microsoft.PowerShell.Core\Registry::" + $RegPath) -ErrorAction SilentlyContinue
        
            $RegPath = "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\" + $($DeviceObject.InstanceId) + "\Device Parameters\WinBio\Configurations\1"
            if ( $MyDebug ) { Write-Host "RegKey - RegSubFolders '1' - query existence" }
            $ConfigurationFolder1_exists = Get-Item -Path ("Microsoft.PowerShell.Core\Registry::" + $RegPath) -ErrorAction SilentlyContinue
            if ( $ConfigurationFolder0_exists -and $ConfigurationFolder1_exists )    { $DeviceObject.Capabilities_FPR_Reg_ConfigFolders = $True }
            
            # summary of RegSubFolders
            Write-Output "Result from Registry:  Device '$($DeviceObject.deviceName)' - ESS capability registry query part 2o2: ('TWO Configuration-Folders' exist) = $($DeviceObject.Capabilities_FPR_Reg_ConfigFolders)`r`n"
            }

        # summary of all registry results
        if ( $DeviceObject.Capabilities_FPR_Reg_ConfigFolders -and $DeviceObject.Capabilities_FPR_REG_Secure )     { $DeviceObject.Capabilities_FPR_Reg_Summary = $True }
        else                                                                                                       { $DeviceObject.Capabilities_FPR_Reg_Summary = $False }
            
        Write-Output "Result from Registry:  Device '$($DeviceObject.deviceName)' is ESS-Capable (registry result) = $($DeviceObject.Capabilities_FPR_Reg_Summary )`r`n"
        
        # summary of 'registry results' and 'Capabilities_SECUREDEVICE' ( CM_DEVCAP_SECUREDEVICE )
        if ( $DeviceObject.Capabilities_FPR_Reg_Summary -or $DeviceObject.Capabilities_SECUREDEVICE )              { $DeviceObject.ESS_Capable__REG_and_DEVCAP_SECUREDEVICE = $True }
        else                                                                                                       { $DeviceObject.ESS_Capable__REG_and_DEVCAP_SECUREDEVICE = $False }
        

        
        $DeviceObject | ft | out-string | write-Host
        $AllDeviceObjects += $DeviceObject 
    } 
else 
    {
    Write-Output "Fingerprint Reader: Not Found"
    }
<#

#>




# Get USB host controllers
# 'Intel(R) USB 3.1 eXtensible Host Controller - 1.10 (Microsoft)'   148 = 128+16+4    => REMOVABLE (0x0004=4) , UNIQUEID (0x0010=16), SURPRISEREMOVALOK (0x0080=128)
$hostControllers = @()
$hostControllers = Get-PnpDevice  -ErrorAction SilentlyContinue | Where-Object { $_.FriendlyName -like "*eXtensible Host Controller*" } 
$hostControllersNames = $hostControllers | Select-Object -ExpandProperty FriendlyName | Sort-Object
Write-Host "------------------------------------"
if ($hostControllersNames) 
    {
    Write-Output "following 'eXtensible Host Controller(s)' are detected:    '$($hostControllersNames -join "', '")'"
    foreach ($controller in $hostControllers) { 
        $DeviceObject = Check-DeviceCapabilities__CM_DEVCAP_SECUREDEVICE_for_WHfB_ESS -deviceName $controller.FriendlyName 
        $DeviceObject | ft | out-string | write-Host
        $AllDeviceObjects += $DeviceObject 
        }
    } 
else 
    {
    Write-Output "eXtensible Host Controller: Not Found"
    }

# clear-host
# Get cameras
# 'Intel(R) MTL AVStream Camera'     224                  ->                        SILENTINSTALL (0x0020 = 32), RAWDEVICEOK (0x0040 = 64), SURPRISEREMOVALOK (0x0080=128)
# 'USB 2.0 Camera'  (DevMgmt.Msc)    164 = 4 + 32 + 128   -> REMOVABLE (0x0004=4)   SILENTINSTALL (0x0020 = 32)                             SURPRISEREMOVALOK (0x0080=128)
$cameras = @()
$cameras = Get-PnpDevice -Class Camera -PresentOnly  -ErrorAction SilentlyContinue
$CameraNames = $cameras | Select-Object -ExpandProperty FriendlyName | Sort-Object
Write-Host "------------------------------------"
if ($CameraNames) 
    {
    Write-Output "following 'Camera(s)' are detected:    '$($CameraNames -join "', '")'"
    foreach ($camera in $cameras) { 
        $DeviceObject = Check-DeviceCapabilities__CM_DEVCAP_SECUREDEVICE_for_WHfB_ESS -deviceName $camera.FriendlyName 
        $DeviceObject | ft | out-string | write-Host
        $AllDeviceObjects += $DeviceObject 
        }
    } 
else 
    {
    Write-Output "Camera: Not Found"
    }

#IR Camera Detection
$irCameraDevices = @()
#camera class (most reliable for hardware)
$irCameraDevices += Get-PnpDevice -Class Camera -Status OK -ErrorAction SilentlyContinue `
    | Where-Object { $_.FriendlyName -match '(?i)(IR\s?Camera|RealSense|Depth\sCamera|Infrared\sCamera|Windows Hello|Facial Recognition|IR)' }
#biometric class (Facial Recognition (Windows Hello) Software Device)
$irCameraDevices += Get-PnpDevice -Class Biometric -Status OK -ErrorAction SilentlyContinue `
    | Where-Object { $_.FriendlyName -match '(?i)(IR\s?Camera|RealSense|Depth\sCamera|Infrared\sCamera|Windows Hello|Facial Recognition|IR)' }
$irNames = $irCameraDevices | Select-Object -ExpandProperty FriendlyName | Sort-Object

Write-Host "------------------------------------"
if ($irNames) 
    {
    Write-Output "following 'IR Camera(s)' are detected:    '$($irNames -join ', ')'"
    foreach ($irCameraDevice in $irCameraDevices) { 
        $DeviceObject  = Check-DeviceCapabilities__CM_DEVCAP_SECUREDEVICE_for_WHfB_ESS -deviceName $irCameraDevice.FriendlyName 
        $DeviceObject | ft | out-string | write-Host
        $AllDeviceObjects += $DeviceObject 
        }
    } 
else 
    {
    Write-Output "IR Camera: Not Found"
    }

Write-Host

$AllDeviceObjects  | ft | out-string | write-Host

$AllDeviceObjects  | select deviceName,InstanceId,Class,Capabilities_SECUREDEVICE,Capabilities_FPR_Reg_Summary | ft | out-string | write-Host


#########################################################################
#
# Summary   device information
#
#########################################################################
# $essCapableDevices
if ($essCapableDevices) { Write-Output "The devices of this computer are     'Windows Hello ESS' capable (Windows Hello Enhanced Sign-in Security)"; Return 0 }
else                    { Write-Output "The devices of this computer are not 'Windows Hello ESS' capable (Windows Hello Enhanced Sign-in Security)"; Return 1 }