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

    $devices = Get-PnpDevice | Where-Object { $_.FriendlyName -like "*$deviceName*" -and $_.Status -eq 'OK'}
    if ($devices) 
        {
        ForEach ( $device in $devices )
            {
            Write-Host "Check-DeviceCapabilities() '$deviceName' - '$($device.InstanceId)' - " -NoNewline

            $DevProperties = Get-PnpDevice -InstanceId $($device.InstanceId) | Get-PnpDeviceProperty
            <#
                ($DevProperties | Where { $_.KeyName -eq "DEVPKEY_Device_Class" }).Data           #  = 'Biometric' 
                ($DevProperties | Where { $_.KeyName -eq "DEVPKEY_Device_Parent" }).Data          #  = 'USB\ROOT_HUB30\4&de9ba18&0&0'
                ($DevProperties | Where { $_.KeyName -eq "DEVPKEY_Device_ConfigurationId" }).Data #  = 'oem28.inf:USB\VID_27C6&PID_634C,MyDevice_Install.NT'
                ($DevProperties | Where { $_.KeyName -eq "DEVPKEY_Device_InstallDate" }).Data     #  = 'Freitag, 13. Februar 2026 14:05:06'
                ($DevProperties | Where { $_.KeyName -eq "DEVPKEY_Device_DriverProvider" }).Data  #  = 'Goodix'
                ($DevProperties | Where { $_.KeyName -eq "DEVPKEY_Device_DriverDesc" }).Data      #  = 'Goodix MOC Fingerprint'
                ($DevProperties | Where { $_.KeyName -eq "DEVPKEY_Device_DriverVersion" }).Data   #  = '3.4.340.330'
                ($DevProperties | Where { $_.KeyName -eq "DEVPKEY_Device_DriverDate" }).Data      #  = 'Sonntag, 10. Dezember 2023 01:00:00'
                ($DevProperties | Where { $_.KeyName -eq "DEVPKEY_Device_Capabilities" }).Data    #  =  Integer or 0
                ($DevProperties | Where { $_.KeyName -eq "DEVPKEY_Device_Service" }).Data         #  =  usbaudio   or   usbvideo    or   camera
             #>           
             
             if ( ($DevProperties | Where { $_.KeyName -eq "DEVPKEY_Device_Service" }).Data -eq 'usbaudio'  -or `
                  ($DevProperties | Where { $_.KeyName -eq "DEVPKEY_Device_Class" }).Data -eq 'AudioEndpoint' )
                {
                # skip this '$device.InstanceId' because it is an AUDIO device - e.g. 'Microphone' 
                 Write-Host "SKIPPED`r`nCheck-DeviceCapabilities() --- because USBAUDIO (e.g. microphone in camera  or  audio-software)`r`n" -ForegroundColor Red
                }
            else
                {
                $deviceCapabilities =  ($DevProperties | Where { $_.KeyName -eq "DEVPKEY_Device_Capabilities" })
                if ( $deviceCapabilities )
                    {
                    [DeviceCapabilities]$DevCap = (Get-PnpDeviceProperty -InstanceId $($device.InstanceId) -KeyName DEVPKEY_Device_Capabilities).Data -as [DeviceCapabilities]
                    Write-Host $DevCap 
                    if ($deviceCapabilities.Data -band 0x0400) 
                        {
                        if ( $MyDebug ) { Write-Output "Check-DeviceCapabilities() -- '$deviceName' is ESS-capable." }
                        $essCapableDevices += $deviceName + " --- " + $($device.InstanceId)
                        }
                    else 
                        {
                        Write-Output "Check-DeviceCapabilities() -- '$deviceName' is not ESS-capable." 
                        $DriverDetails = ""
                        $DriverDetails = $DriverDetails + "`r`nClass:        " + ($DevProperties | Where { $_.KeyName -eq "DEVPKEY_Device_Class" }).Data           #  = 'Biometric' 
                        $DriverDetails = $DriverDetails + "`r`nService:      " + ($DevProperties | Where { $_.KeyName -eq "DEVPKEY_Device_Service" }).Data         # 
                        $DriverDetails = $DriverDetails + "`r`nParent:       " + ($DevProperties | Where { $_.KeyName -eq "DEVPKEY_Device_Parent" }).Data          #  = 'USB\ROOT_HUB30\4&de9ba18&0&0'
                        $DriverDetails = $DriverDetails + "`r`nDriver:       " + ($DevProperties | Where { $_.KeyName -eq "DEVPKEY_Device_ConfigurationId" }).Data #  = 'oem28.inf:USB\VID_27C6&PID_634C,MyDevice_Install.NT'
                        $DriverDetails = $DriverDetails + "`r`nInstallDate:  " + ($DevProperties | Where { $_.KeyName -eq "DEVPKEY_Device_InstallDate" }).Data     #  = 'Freitag, 13. Februar 2026 14:05:06'
                        $DriverDetails = $DriverDetails + "`r`nProvider:     " + ($DevProperties | Where { $_.KeyName -eq "DEVPKEY_Device_DriverProvider" }).Data  #  = 'Goodix'
                        $DriverDetails = $DriverDetails + "`r`nDescription:  " + ($DevProperties | Where { $_.KeyName -eq "DEVPKEY_Device_DriverDesc" }).Data      #  = 'Goodix MOC Fingerprint'
                        $DriverDetails = $DriverDetails + "`r`nVersion:      " + ($DevProperties | Where { $_.KeyName -eq "DEVPKEY_Device_DriverVersion" }).Data   #  = '3.4.340.330'
                        $DriverDetails = $DriverDetails + "`r`nDriver-Date:  " + ($DevProperties | Where { $_.KeyName -eq "DEVPKEY_Device_DriverDate" }).Data      #  = 'Sonntag, 10. Dezember 2023 01:00:00'
                        $DriverDetails = $DriverDetails + "`r`nCapabilities: " + ($DevProperties | Where { $_.KeyName -eq "DEVPKEY_Device_Capabilities" }).Data + " = " + $DevCap     #  =  Integer or 0
                        Write-Host "Check-DeviceCapabilities() -- Current Driver - Details`r`n$DriverDetails`r`n"
                        }
                    }
                else
                    {
                    Write-Host
                    Write-Output "Check-DeviceCapabilities() Devices like '$deviceName' - 'Get-PnpDeviceProperty()' returned NULL."
                    }
                } # END     NOT ($DevProperties | Where { $_.KeyName -eq "DEVPKEY_Device_Service" }).Data -eq 'usbaudio'
            } # END   ForEach ( $device in $devices )
        }
    else 
        {
        Write-Output "Check-DeviceCapabilities() Device '$deviceName' not found."
        }
    }



#########################################################################
#
# collect device information
#
#########################################################################

Clear-Host
$essCapableDevices = @()



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
    Write-Output "following 'Fingerprint Reader(s)' are detected:    '$($fpNames -join -join "', '")'"
    foreach ($FingerprintDevice in $fingerprintDevices) { 
        
        Check-DeviceCapabilities__CM_DEVCAP_SECUREDEVICE_for_WHfB_ESS -deviceName $FingerprintDevice.FriendlyName }
        $FPR_InstanceID = $FingerprintDevice.InstanceID 
        
        #  $FPR_InstanceID = (Get-PnpDevice -Class Biometric -Status OK -ErrorAction SilentlyContinue  | Where { $_.FriendlyName -like "*Fingerprint*" }).InstanceId
        #  $FPR_InstanceID                                # USB\VID_27C6&PID_634C\UID8C267D71_XXXX_MOC_B0
        #
        #  Path from RegEdit
        #  HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\USB\VID_27C6&PID_634C\UID8C267D71_XXXX_MOC_B0\Device Parameters\WinBio\Configurations
        
        $RegPath = "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\" + $FPR_InstanceID + "\Device Parameters\WinBio\Configurations"
        Write-Host "`r`n`r`nRegKey  '$RegPath'   -  'SecureFingerprint' should be '1'"

        #
        #   Because of the '&' ( part of InstanceID )  in the RegPath   use '"Microsoft.PowerShell.Core\Registry:'
        #

        # Get-Item -Path "Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\USB\VID_27C6&PID_634C\UID8C267D71_XXXX_MOC_B0\Device Parameters\WinBio\Configurations"
        # Get-Item -Path ("Microsoft.PowerShell.Core\Registry::" + $RegKey)
        #
        #               Name                           Property                                                                                                                                                         
        #               ----                           --------                                                                                                                                                         
        #               Configurations                 DefaultConfiguration       : 0                                                                                                                                   
        #                                              SecureFingerprint          : 1                                                                                                                                   
        #                                              VirtualSecureConfiguration : 1      
        # Get-ItemProperty -Path ("Microsoft.PowerShell.Core\Registry::" + $RegPath) -Name SecureFingerprint
        
        # There should be a registry key listed named 'SecureFingerprint' with a data value of 1. If it doesn't exist, the device isn't secure-capable.
        $SecureFingerprintValue = Get-ItemPropertyValue -Path ("Microsoft.PowerShell.Core\Registry::" + $RegPath) -Name SecureFingerprint  -ErrorAction SilentlyContinue
        if ( $SecureFingerprintValue )
            {
            if ( $SecureFingerprintValue -eq 1 )
                {
                $Fingerprint_ESS_Capable = $True
                }
            else
                {
                $Fingerprint_ESS_Capable = $False
                }
            }
        else
            {
            $Fingerprint_ESS_Capable = $False
            }  
            Write-Output "Result from Registry:  Device '$($FingerprintDevice.FriendlyName)' is ESS-Capable ('SecureFingerprint' eq 1) = $Fingerprint_ESS_Capable`r`n`r`n"
    
        # Configurations should also have two folders beneath it: one labeled 0 and one labeled 1. 
        # If there's only one folder and not two, the device isn't secure-capable.
        $RegPath = "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\" + $FPR_InstanceID + "\Device Parameters\WinBio\Configurations\0"
        Write-Host "`r`n`r`nRegKey  '$RegPath - query existence"
        $ConfigurationFolder0_exists = Get-Item -Path ("Microsoft.PowerShell.Core\Registry::" + $RegPath) -ErrorAction SilentlyContinue
        
        $RegPath = "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\" + $FPR_InstanceID + "\Device Parameters\WinBio\Configurations\1"
        Write-Host "RegKey  '$RegPath - query existence"
        $ConfigurationFolder1_exists = Get-Item -Path ("Microsoft.PowerShell.Core\Registry::" + $RegPath) -ErrorAction SilentlyContinue
        if ( $ConfigurationFolder0_exists -and $ConfigurationFolder1_exists )
            {
            $ConfigurationFolders_exist = $True
            }
        else
            {
            $ConfigurationFolders_exist = $False
            }  
        
              
        Write-Output "Result from Registry:  Device '$($FingerprintDevice.FriendlyName)' is ESS-Capable ('TWO Configuration-Folders' exist) = $ConfigurationFolders_exist`r`n`r`n"
    } 
else 
    {
    Write-Output "Fingerprint Reader: Not Found"
    }
<#
    
    Fingerprint Reader(s): Goodix MOC Fingerprint
    Check-DeviceCapabilities() 'Goodix MOC Fingerprint' - 'USB\VID_27C6&PID_634C\UID8C267D71_XXXX_MOC_B0' - UNIQUEID, SURPRISEREMOVALOK
    Check-DeviceCapabilities() -- 'Goodix MOC Fingerprint' is not ESS-capable.
    Check-DeviceCapabilities() -- Current Driver - Details

    before 'Dell Command Update'

    Class:        Biometric
    Service:      WUDFRd
    Parent:       USB\ROOT_HUB30\4&de9ba18&0&0
    Driver:       oem28.inf:USB\VID_27C6&PID_634C,MyDevice_Install.NT
    InstallDate:  02/13/2026 14:05:06
    Provider:     Goodix
    Description:  Goodix MOC Fingerprint
    Version:      3.4.340.330
    Driver-Date:  12/10/2023 01:00:00
    Capabilities: 144 = UNIQUEID, SURPRISEREMOVALOK

    after 'Dell Command Update'   - only three changes - not really related to ESS
    
    InstallDate:  02/13/2026 16:52:39
    Version:      3.4.340.370
    Driver-Date:  01/07/2025 01:00:00
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
    foreach ($controller in $hostControllers) { Check-DeviceCapabilities__CM_DEVCAP_SECUREDEVICE_for_WHfB_ESS -deviceName $controller.FriendlyName }
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
    foreach ($camera in $cameras) { Check-DeviceCapabilities__CM_DEVCAP_SECUREDEVICE_for_WHfB_ESS -deviceName $camera.FriendlyName }
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
    foreach ($irCameraDevice in $irCameraDevices) { Check-DeviceCapabilities__CM_DEVCAP_SECUREDEVICE_for_WHfB_ESS -deviceName $irCameraDevice.FriendlyName }
    } 
else 
    {
    Write-Output "IR Camera: Not Found"
    }

Write-Host
#########################################################################
#
# Summary   device information
#
#########################################################################
# $essCapableDevices
if ($essCapableDevices) { Write-Output "The devices of this computer are     'Windows Hello ESS' capable (Windows Hello Enhanced Sign-in Security)"; Return 0 }
else                    { Write-Output "The devices of this computer are not 'Windows Hello ESS' capable (Windows Hello Enhanced Sign-in Security)"; Return 1 }