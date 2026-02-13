
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

Function Get-EventViewer_WinEvents__By_LogName_and_ID
    {
    param ( [string]$LogPath , [string]$EventID , [Switch]$MyDebug)

    # Example:  
    #    $WinEvents_Biometric1108_All = Get-EventViewer_WinEvents__By_LogName_and_ID -LogPath "Microsoft-Windows-Biometrics/Operational" -EventID 1108 -MyDebug

    # Check if the log exists
    if (Get-WinEvent -ListLog $LogPath -ErrorAction SilentlyContinue) {
        if ( $MyDebug ) { Write-Host "Retieving WinEvents from EventVwr-log '$LogPath' for Event ID '$EventID'" }
        $WinEvents = Get-WinEvent -LogName $LogPath -FilterXPath "*[System[EventID=$EventID]]"  -ErrorAction SilentlyContinue
        }  
    else 
        {
        $WinEvents = $Null
        if ( $MyDebug ) { Write-Host "The specified log path '$LogPath' does not exist or is not accessible." }
        }  
   return $WinEvents
    }

Function Query-WinEvents__Message_match_SearchString
    {
    param ( [Array]$arrWinEvents , [string]$SearchString , [Switch]$MyDebug)

    # Example:  
    #    $WinEvents_Biometric1108_VirtualSecureMode = Query-WinEvents__Message_match_SearchString -arrWinEvents $WinEvents_Biometric1108_All -SearchString "Virtual Secure Mode" -MyDebug

    if ( $Null -eq $arrWinEvents)         {
        if ( $MyDebug ) { Write-Host "WinEvents_SearchForString('$SearchString') - paramter 'arrWinEvents' is NULL / EMPTY - returning NULL" -ForegroundColor Red }
        Return $NULL
        }
    else {
        if ( $MyDebug ) { 
            Write-Host "WinEvents_SearchForString('$SearchString') - START : 'arrWinEvents' contains $($arrWinEvents.Count) events" 
            $arrWinEvents | FT -AutoSize | Out-String |Write-Host
            }
        }

    $MatchingEvents = @()
    $MatchingEvents += $arrWinEvents | Where-Object { $_.Message -like "*$SearchString*"  }
    if ($MatchingEvents) {
        if ( $MyDebug ) { 
            Write-Host "WinEvents_SearchForString() - Events containing the text '$SearchString':`n"
            $MatchingEvents | FT -AutoSize | Out-String | Write-Host
            Write-Host "------------------------------------"
            Write-Host "WinEvents_SearchForString('$SearchString') - END : 'MatchingEvents' contains $($MatchingEvents.Count) events"  
            }
        return $MatchingEvents 
        }
    else {
        if ( $MyDebug )  {  Write-Host "WinEvents_SearchForString() - No events containing the text '$SearchString' were found - returning NULL" -ForegroundColor Red }
        return $NULL
        }
    }

Function Remove-WinEvents__Message_StringToDelete
    {
    param ( [Array]$arrWinEvents , [string]$StringToDelete , [Switch]$MyDebug)

    # Example:  
    #    $WinEvents_Biometric1108_All = Remove-WinEvents__Message_StringToDelete -arrWinEvents $WinEvents_Biometric1108_All -StringToDelete $DeleteMeFromMessage -MyDebug

    if ( $Null -eq $arrWinEvents)         {
        if ( $MyDebug ) { Write-Host "WinEvents_StringToDelete() - paramter 'arrWinEvents' is NULL / EMPTY - returning NULL" -ForegroundColor Red }
        Return $NULL
        }
    else {
        if ( $MyDebug ) { 
            Write-Host "Message_StringToDelete() - 'arrWinEvents' contains $($arrWinEvents.Count) events" 
            $arrWinEvents | FT -wrap | Out-String |Write-Host
            }
        }

    ForEach ( $Event in $arrWinEvents)
        {
        if ( $Event.Message -like "*$StringToDelete*"  )
            {
            $Event.Message = ($Event.Message).Replace($StringToDelete, "")
           # $Event.Message
            }
        }

    return $arrWinEvents 
    }

clear-Host
<#
    Biometric events in Windows, such as fingerprint or facial recognition usage, are recorded in the Event Viewer under 
            Applications and Services Logs > Microsoft > Windows > Biometrics > Operational
    
    1108 - The most critical event ID is 1108, which confirms whether a biometric device (sensor) is properly loaded and initialized. 
    1004 - Biometric successful
    
    # following is related to Policies 
    # - Login audit should be enabled by default (at least successful attempts for older Windows). 
    # - if not, you can enable it in Policies: Computer\Configuration\Windows Settings\Security Settings\Local Policies\Audit Policy
    4624 - (Security Log) Windows login successful, identifying if biometrics were used. 
           - recording the username, time, and logon type. 
           - Key details include Logon Type (e.g., 2=Interactive, 3=Network, 7=Workstation was unlocked, 10=RDP) and Logon ID.
           - https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/basic-audit-logon-events
    4648 - (Security Log) Windows login in as additional user 

#>
#########################################################################
#
# collect Windows Events
#
#########################################################################
#   'Goodix MOC Fingerprint' - 'USB\VID_27C6&PID_634C\UID8C267D71_XXXX_MOC_B0' - UNIQUEID, SURPRISEREMOVALOK

$WinEvents_Biometric = @()

$AllBioMetricEventIDs = (Get-WinEvent -FilterHashtable @{ProviderName='microsoft-windows-Biometrics'}  -ErrorAction SilentlyContinue) `
    | Where-Object { $_.TimeCreated -ge $Today }   `
    | select ID -Unique `
    | sort ID
# $AllBioMetricEventIDs    # on my test PC      =>      Id = 1105,1108,1109,1601

#########################################################################
# Get EventViewer Biometrics-log - all ID=1004 
#     "The Windows Biometric Service successfully identified <hostname>\<username> (SID) using sensor: 
#     VeriMark DT Fingerprint Key (USB\VID_047D&PID_00F2&MI_01\7&163AA6B8&0&0001)."
#########################################################################
$WinEvents_Biometric1004_All = Get-EventViewer_WinEvents__By_LogName_and_ID -LogPath "Microsoft-Windows-Biometrics/Operational" -EventID 1004
$Today = (Get-Date).Date
$WinEvents_Biometric1004_All = $WinEvents_Biometric1004_All | Where-Object { $_.TimeCreated -ge $Today }   `
# $WinEvents_Biometric1004_All | FT -Wrap | Out-String |Write-Host
$WinEvents_Biometric += $WinEvents_Biometric1004_All

#########################################################################
# Get EventViewer Biometrics-log - all ID=1018   
#########################################################################
$WinEvents_Biometric1018_All = Get-EventViewer_WinEvents__By_LogName_and_ID -LogPath "Microsoft-Windows-Biometrics/Operational" -EventID 1018
$Today = (Get-Date).Date
$WinEvents_Biometric1018_All = $WinEvents_Biometric1018_All | Where-Object { $_.TimeCreated -ge $Today }   `

$DeleteMeFromMessage = 'The Windows Biometric Service successfully started its secure component.'
# $WinEvents_Biometric1018_All = Remove-WinEvents__Message_StringToDelete -arrWinEvents $WinEvents_Biometric1018_All -StringToDelete $DeleteMeFromMessage 

# $WinEvents_Biometric1018_All | FT -Wrap | Out-String |Write-Host
$WinEvents_Biometric += $WinEvents_Biometric1018_All


#########################################################################
# Get EventViewer Biometrics-log - all ID=1019   
#     "The Windows Biometric Service completed a privileged vendor-specific operation for sensor: 
#      Facial Recognition (Windows Hello) Software Device (ROOT\WINDOWSHELLOFACESOFTWAREDRIVER\0000).
#      The command was directed to the biometric unit's 'Sensor Adapter' component."
#########################################################################
$WinEvents_Biometric1019_All = Get-EventViewer_WinEvents__By_LogName_and_ID -LogPath "Microsoft-Windows-Biometrics/Operational" -EventID 1019
$Today = (Get-Date).Date
$WinEvents_Biometric1019_All = $WinEvents_Biometric1019_All | Where-Object { $_.TimeCreated -ge $Today }   `
# $WinEvents_Biometric1019_All | FT -Wrap | Out-String |Write-Host
$WinEvents_Biometric += $WinEvents_Biometric1019_All


#########################################################################
# Get EventViewer Biometrics-log - all ID=1104   
# Indicates a successful biometric scan.
#########################################################################
$WinEvents_Biometric1104_All = Get-EventViewer_WinEvents__By_LogName_and_ID -LogPath "Microsoft-Windows-Biometrics/Operational" -EventID 1104
$Today = (Get-Date).Date
$WinEvents_Biometric1104_All = $WinEvents_Biometric1104_All | Where-Object { $_.TimeCreated -ge $Today }   `
# $WinEvents_Biometric1104_All | FT -Wrap | Out-String |Write-Host
$WinEvents_Biometric += $WinEvents_Biometric1104_All

#########################################################################
# Get EventViewer Biometrics-log - all ID=1105
#########################################################################
$WinEvents_Biometric1105_All = Get-EventViewer_WinEvents__By_LogName_and_ID -LogPath "Microsoft-Windows-Biometrics/Operational" -EventID 1105
$Today = (Get-Date).Date
$WinEvents_Biometric1105_All = $WinEvents_Biometric1105_All | Where-Object { $_.TimeCreated -ge $Today }   `

$DeleteMeFromMessage = 'The Windows Biometric Service failed to initialize an adapter binary: '
$WinEvents_Biometric1105_All = Remove-WinEvents__Message_StringToDelete -arrWinEvents $WinEvents_Biometric1105_All -StringToDelete $DeleteMeFromMessage 

$DeleteMeFromMessage = "See the ""Details"" pane for information about the failing configuration."
$WinEvents_Biometric1105_All = Remove-WinEvents__Message_StringToDelete -arrWinEvents $WinEvents_Biometric1105_All -StringToDelete $DeleteMeFromMessage 

$DeleteMeFromMessage = "The module's ""Sensor Adapter"""
$WinEvents_Biometric1105_All = Remove-WinEvents__Message_StringToDelete -arrWinEvents $WinEvents_Biometric1105_All -StringToDelete $DeleteMeFromMessage

$DeleteMeFromMessage = 'routine '
$WinEvents_Biometric1105_All = Remove-WinEvents__Message_StringToDelete -arrWinEvents $WinEvents_Biometric1105_All -StringToDelete $DeleteMeFromMessage 

# https://learn.microsoft.com/en-us/answers/questions/4027263/facial-recognition-in-windows-hello-stopped-workin
# WINBIO_E_SENSOR_UNAVAILABLE 0x80098034	A private pool cannot be created because one or more biometric units are not available.

# $WinEvents_Biometric1105_All | FT -Wrap | Out-String |Write-Host
$WinEvents_Biometric += $WinEvents_Biometric1105_All


#########################################################################
# Get EventViewer Biometrics-log - all ID=1108 
# Confirms whether a biometric device (sensor) is properly loaded and initialized.
# Confirms the sensor (fingerprint or camera) is operating correctly. 
# If Enhanced Sign-in Security (ESS) is enabled, the device is isolated in a "Virtual Secure Mode" process. 
# https://learn.microsoft.com/en-us/windows/win32/secbiomet/client-error-codes

# Goodix MOC Fingerprint (USB\VID_27C6&PID_634C\UID8C267D71_XXXX_MOC_B0)The sensor's mode is "Advanced," its pool-type is "System," and it's isolated in a "Virtual Secure Mode" process.                                                            

#########################################################################
$WinEvents_Biometric1108_All = Get-EventViewer_WinEvents__By_LogName_and_ID -LogPath "Microsoft-Windows-Biometrics/Operational" -EventID 1108

$Today = (Get-Date).Date
$WinEvents_Biometric1108_All = $WinEvents_Biometric1108_All | Where-Object { $_.TimeCreated -ge $Today }   `

$DeleteMeFromMessage = 'The Windows Biometric Service successfully created a Biometric Unit for sensor: '
$WinEvents_Biometric1108_All = Remove-WinEvents__Message_StringToDelete -arrWinEvents $WinEvents_Biometric1108_All -StringToDelete $DeleteMeFromMessage 

# See the "Details" pane for additional information about the sensor's new configuration.
$DeleteMeFromMessage = "See the ""Details"" pane for additional information about the sensor's new configuration."
$WinEvents_Biometric1108_All = Remove-WinEvents__Message_StringToDelete -arrWinEvents $WinEvents_Biometric1108_All -StringToDelete $DeleteMeFromMessage 

# The "Analog NUI Voice Virtual Sensor" is a component of the Windows Biometric Service (WBS), 
# often appearing in system logs or device management, which acts as a software-based (virtual) sensor for voice input. 
# It enables biometric authentication and Natural User Interface (NUI) features in Windows, 
# allowing user voice recognition without a physical, dedicated analog microphone sensor. 
$DeleteMeFromMessage = 'Analog NUI Voice Virtual Sensor (\Voice\Virtual Sensors\{F25AB4A2-593A-4A89-B9FF-8144BEA81E15})'
# $WinEvents_Biometric1108_All = Remove-WinEvents__Message_StringToDelete -arrWinEvents $WinEvents_Biometric1108_All -StringToDelete $DeleteMeFromMessage

$DeleteMeFromMessage = 'Windows Hello Face Virtual Software Device (\Bootstrap\Virtual Sensors\{0527b250-7514-4321-8b68-41c65f956998})'
# $WinEvents_Biometric1108_All = Remove-WinEvents__Message_StringToDelete -arrWinEvents $WinEvents_Biometric1108_All -StringToDelete $DeleteMeFromMessage 

#$WinEvents_Biometric1108_All | FT -Wrap | Out-String |Write-Host

$WinEvents_Biometric += $WinEvents_Biometric1108_All

#########################################################################
# Get EventViewer Biometrics-log - all ID=1109
#########################################################################
$WinEvents_Biometric1109_All = Get-EventViewer_WinEvents__By_LogName_and_ID -LogPath "Microsoft-Windows-Biometrics/Operational" -EventID 1109
$Today = (Get-Date).Date
$WinEvents_Biometric1109_All = $WinEvents_Biometric1109_All | Where-Object { $_.TimeCreated -ge $Today }   `

$DeleteMeFromMessage = 'The Windows Biometric Service failed to configure a Biometric Unit for sensor: '
$WinEvents_Biometric1109_All = Remove-WinEvents__Message_StringToDelete -arrWinEvents $WinEvents_Biometric1109_All -StringToDelete $DeleteMeFromMessage 

$DeleteMeFromMessage = "See the ""Details"" pane for information about the failing configuration."
$WinEvents_Biometric1109_All = Remove-WinEvents__Message_StringToDelete -arrWinEvents $WinEvents_Biometric1109_All -StringToDelete $DeleteMeFromMessage 


# https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/winbio_ioctl/ns-winbio_ioctl-_winbio_sensor_attributes
#        WINBIO_SENSOR_ATTRIBUTES structure (winbio_ioctl.h)
#
# Facial Recognition (Windows Hello) Software Device (ROOT\WINDOWSHELLOFACESOFTWAREDRIVER\0000).The operation failed with error: 0x80098057 
#
# https://learn.microsoft.com/en-us/answers/questions/4027263/facial-recognition-in-windows-hello-stopped-workin
# WINBIO_E_INSECURE_SENSOR 0x80098057	The biometric sensor does not support a secure hardware data path.

#
# Facial Recognition (Windows Hello) Software Device (ROOT\WINDOWSHELLOFACESOFTWAREDRIVER\0000).The operation failed with error: 0x80098036  
#
# https://learn.microsoft.com/en-us/windows/win32/secbiomet/client-error-codes
# WINBIO_E_DEVICE_FAILURE  0x80098036   A biometric sensor has failed.
#    This error indicates that a biometric sensor (fingerprint reader or facial recognition camera) has failed or cannot communicate with the Windows Hello service. 
#
#
# $WinEvents_Biometric1109_All | FT -Wrap | Out-String |Write-Host

$WinEvents_Biometric += $WinEvents_Biometric1109_All

#########################################################################
# Get EventViewer Biometrics-log - all ID=1601
#########################################################################
$WinEvents_Biometric1601_All = Get-EventViewer_WinEvents__By_LogName_and_ID -LogPath "Microsoft-Windows-Biometrics/Operational" -EventID 1601
$Today = (Get-Date).Date
$WinEvents_Biometric1601_All = $WinEvents_Biometric1601_All | Where-Object { $_.TimeCreated -ge $Today }   `

$DeleteMeFromMessage = 'The Windows Biometric Service successfully started its secure component.'
# $WinEvents_Biometric1601_All = Remove-WinEvents__Message_StringToDelete -arrWinEvents $WinEvents_Biometric1601_All -StringToDelete $DeleteMeFromMessage 

# $WinEvents_Biometric1601_All | FT -Wrap | Out-String |Write-Host
$WinEvents_Biometric += $WinEvents_Biometric1601_All

#########################################################################
# Get EventViewer Biometrics-log - all ID=1605
# "The Windows Biometric Service secure component successfully authorized user (domain)<user>"
#########################################################################
$WinEvents_Biometric1605_All = Get-EventViewer_WinEvents__By_LogName_and_ID -LogPath "Microsoft-Windows-Biometrics/Operational" -EventID 1605
$Today = (Get-Date).Date
$WinEvents_Biometric1605_All = $WinEvents_Biometric1605_All | Where-Object { $_.TimeCreated -ge $Today }   `

$DeleteMeFromMessage = 'The Windows Biometric Service successfully started its secure component.'
# $WinEvents_Biometric1605_All = Remove-WinEvents__Message_StringToDelete -arrWinEvents $WinEvents_Biometric1605_All -StringToDelete $DeleteMeFromMessage 

# $WinEvents_Biometric1605_All | FT -Wrap | Out-String |Write-Host
$WinEvents_Biometric += $WinEvents_Biometric1605_All

#########################################################################
# Get EventViewer Biometrics-log - all ID=1606 
#########################################################################
$WinEvents_Biometric1606_All = Get-EventViewer_WinEvents__By_LogName_and_ID -LogPath "Microsoft-Windows-Biometrics/Operational" -EventID 1606
$Today = (Get-Date).Date
$WinEvents_Biometric1606_All = $WinEvents_Biometric1606_All | Where-Object { $_.TimeCreated -ge $Today }   `

$DeleteMeFromMessage = 'The Windows Biometric Service successfully started its secure component.'
# $WinEvents_Biometric1606_All = Remove-WinEvents__Message_StringToDelete -arrWinEvents $WinEvents_Biometric1606_All -StringToDelete $DeleteMeFromMessage 

# $WinEvents_Biometric1606_All | FT -Wrap | Out-String |Write-Host
$WinEvents_Biometric += $WinEvents_Biometric1606_All

#########################################################################
# Get EventViewer Biometrics-log - all ID=1607 
#########################################################################
$WinEvents_Biometric1607_All = Get-EventViewer_WinEvents__By_LogName_and_ID -LogPath "Microsoft-Windows-Biometrics/Operational" -EventID 1607
$Today = (Get-Date).Date
$WinEvents_Biometric1607_All = $WinEvents_Biometric1607_All | Where-Object { $_.TimeCreated -ge $Today }   `

$DeleteMeFromMessage = 'The Windows Biometric Service successfully started its secure component.'
# $WinEvents_Biometric1607_All = Remove-WinEvents__Message_StringToDelete -arrWinEvents $WinEvents_Biometric1607_All -StringToDelete $DeleteMeFromMessage 

# $WinEvents_Biometric1607_All | FT -Wrap | Out-String |Write-Host
$WinEvents_Biometric += $WinEvents_Biometric1607_All

#########################################################################
# Get EventViewer Biometrics-log - all ID=1608 
#########################################################################
$WinEvents_Biometric1608_All = Get-EventViewer_WinEvents__By_LogName_and_ID -LogPath "Microsoft-Windows-Biometrics/Operational" -EventID 1608
$Today = (Get-Date).Date
$WinEvents_Biometric1608_All = $WinEvents_Biometric1608_All | Where-Object { $_.TimeCreated -ge $Today }   `

$DeleteMeFromMessage = 'The Windows Biometric Service successfully started its secure component.'
# $WinEvents_Biometric1608_All = Remove-WinEvents__Message_StringToDelete -arrWinEvents $WinEvents_Biometric1608_All -StringToDelete $DeleteMeFromMessage 

# $WinEvents_Biometric1608_All | FT -Wrap | Out-String |Write-Host
$WinEvents_Biometric += $WinEvents_Biometric1608_All


#########################################################################
#
# Summary   Windows Events
#
#########################################################################


$WinEvents_Biometric | Sort TimeCreated| FT -Wrap | Out-String |Write-Host

# -------------------------------------------------------
#   filter by InstanceID / DeviceName
# -------------------------------------------------------
# Get EventViewer Biometrics-log - all ID=1108 events containing "Virtual Secure Mode"
$SearchText1 = "(ROOT\WINDOWSHELLOFACESOFTWAREDRIVER\0000)"
$WinEvents_Biometric1108_WHFace_SWDRV = Query-WinEvents__Message_match_SearchString -arrWinEvents $WinEvents_Biometric1108_All -SearchString $SearchText1
if ( $WinEvents_Biometric1108_WHFace_SWDRV -eq $Null )
    {
    $SearchText1 = "Windows Hello Face Virtual Software Device"
    $WinEvents_Biometric1108_WHFace_SWDRV = Query-WinEvents__Message_match_SearchString -arrWinEvents $WinEvents_Biometric1108_All -SearchString $SearchText1
    # $WinEvents_Biometric1108_WHFace_SWDRV | Sort TimeCreated| FT -Wrap | Out-String |Write-Host
    }
$SearchText2 = "Virtual Secure Mode"
$WinEvents_Biometric1108_WHFace_SWDRV_Secure = Query-WinEvents__Message_match_SearchString -arrWinEvents $WinEvents_Biometric1108_WHFace_SWDRV -SearchString $SearchText2
$WinEvents_Biometric1108_WHFace_SWDRV_Secure | FT -Wrap | Out-String |Write-Host

# -------------------------------------------------------
#   filter by sensor's mode   "Basic"   or  "Advanced"
# -------------------------------------------------------
$SearchText3 = "The sensor's mode is ""Basic,"" its pool-type is ""System,"" and it's isolated in a ""Local System"" process."
$SearchText3 = "Basic"
$WinEvents_Biometric1108_Sensor_Basic = Query-WinEvents__Message_match_SearchString -arrWinEvents $WinEvents_Biometric1108_WHFace_SWDRV -SearchString $SearchText3
$WinEvents_Biometric1108_Sensor_Basic | FT -Wrap | Out-String | Write-Host
if ( $WinEvents_Biometric1108_Sensor_Basic )
    {
    Write-output "Sensor is working in 'Basic' and it's isolated in a ""Local System"" process"

    $DeleteMeFromMessage = "The sensor's mode is ""Basic,"" its pool-type is ""System,"" and it's isolated in a ""Local System"" process."
    $WinEvents_Biometric1108_Sensor_Basic = Remove-WinEvents__Message_StringToDelete -arrWinEvents $WinEvents_Biometric1108_Sensor_Basic -StringToDelete $DeleteMeFromMessage 

    $WinEvents_Biometric1108_Sensor_Basic | FT -Wrap | Out-String | Write-Host
    }

$SearchText4 = "The sensor's mode is ""Advanced,"" its pool-type is ""System,"" and it's isolated in a ""Virtual Secure Mode"" process."
$SearchText4 = "Advanced"
$WinEvents_Biometric1108_Sensor_Advanced = Query-WinEvents__Message_match_SearchString -arrWinEvents $WinEvents_Biometric1108_All -SearchString $SearchText4
if ( $WinEvents_Biometric1108_Sensor_Advanced )
    {
    Write-output "Sensor is working in 'Advanced' and it's isolated in a ""Virtual Secure Mode"" process"

    $DeleteMeFromMessage = "The sensor's mode is ""Advanced,"" its pool-type is ""System,"" and it's isolated in a ""Virtual Secure Mode"" process."
    $WinEvents_Biometric1108_Sensor_Advanced = Remove-WinEvents__Message_StringToDelete -arrWinEvents $WinEvents_Biometric1108_Sensor_Advanced -StringToDelete $DeleteMeFromMessage 

    $WinEvents_Biometric1108_Sensor_Advanced | FT -Wrap | Out-String | Write-Host
    }




if ( $WinEvents_Biometric1108_WHFace_SWDRV_Secure )     { Write-Output "ESS is working in 'Virtual Secure Mode'"         }
else                                                    { Write-output "ESS is NOT working in 'Virtual Secure Mode' - please verify"     }




#########################################################################
#
# collect device information
#
#########################################################################




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
Write-Host
if ($fpNames) 
    {
    Write-Output "Fingerprint Reader(s): $($fpNames -join '  ,  ')"
    foreach ($FingerprintDevice in $fingerprintDevices) { Check-DeviceCapabilities__CM_DEVCAP_SECUREDEVICE_for_WHfB_ESS -deviceName $FingerprintDevice.FriendlyName }
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
Write-Host
if ($hostControllersNames) 
    {
    Write-Output "eXtensible Host Controller(s): $($hostControllersNames -join ', ')"
    foreach ($controller in $hostControllers) { Check-DeviceCapabilities__CM_DEVCAP_SECUREDEVICE_for_WHfB_ESS -deviceName $controller.FriendlyName }
    } 
else 
    {
    Write-Output "eXtensible Host Controller: Not Found"
    }


# Get cameras
# 'Intel(R) MTL AVStream Camera'     224                  ->                        SILENTINSTALL (0x0020 = 32), RAWDEVICEOK (0x0040 = 64), SURPRISEREMOVALOK (0x0080=128)
# 'USB 2.0 Camera'  (DevMgmt.Msc)    164 = 4 + 32 + 128   -> REMOVABLE (0x0004=4)   SILENTINSTALL (0x0020 = 32)                             SURPRISEREMOVALOK (0x0080=128)
$cameras = @()
$cameras = Get-PnpDevice -Class Camera -PresentOnly  -ErrorAction SilentlyContinue
$CameraNames = $cameras | Select-Object -ExpandProperty FriendlyName | Sort-Object
Write-Host
if ($CameraNames) 
    {
    Write-Output "Camera(s): $($CameraNames -join '  ,  ')"
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
Write-Host
if ($irNames) 
    {
    Write-Output "IR Camera(s): $($irNames -join ', ')"
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
if ($essCapableDevices) { Write-Output "This computer is     'Windows Hello ESS' capable - 'Windows Hello Enhanced Sign-in Security'."; Return 0 }
else                    { Write-Output "This computer is not 'Windows Hello ESS' capable - 'Windows Hello Enhanced Sign-in Security'."; Return 1 }