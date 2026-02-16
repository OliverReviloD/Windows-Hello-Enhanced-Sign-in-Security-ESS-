
<#
.SYNOPSIS
                Windows Hello Enhanced Sign-in Security
                https://learn.microsoft.com/en-us/windows-hardware/design/device-experiences/windows-hello-enhanced-sign-in-security#system-requirements

                -- Enhanced Sign-in Security (ESS) provides an additional level of security to biometric data with the use of specialized hardware and software components
                - 'Intel(R) USB 3.1 eXtensible Host Controller - 1.10 (Microsoft)'  - check 'Device Properties' - check 'Capabilities' for 'CM_DEVCAP_SECUREDEVICE'
                -- Cameras that support ESS must have this feature built into their firmware, and using the standard Windows UVC camera driver that comes with the operating system is necessary.
                - 'Camera XYZ'  - check 'Device Properties' - check 'Capabilities' for 'CM_DEVCAP_SECUREDEVICE'
                - 'Fingerprint Reader' - get Device 'instance path' ( e.g:  'USB\VID_27C6&PID_634C\UID8C267D71_XXXX_MOC_B0' )
                <#
                    Get-PnpDevice -Class Biometric -Status OK -ErrorAction SilentlyContinue  | Where { $_.FriendlyName -like "*Fingerprint*" }

                    Status     Class           FriendlyName                                          InstanceId     
                    ------     -----           ------------                                          ----------     
                    OK         Biometric       Facial Recognition (Windows Hello) Software Device    ROOT\WINDOWS...
                    OK         Biometric       Goodix MOC Fingerprint                                USB\VID_27C6...

                #>
<#
                $FPR_InstanceID = (Get-PnpDevice -Class Biometric -Status OK -ErrorAction SilentlyContinue  | Where { $_.FriendlyName -like "*Fingerprint*" }).InstanceId
                $FPR_InstanceID # ->   USB\VID_27C6&PID_634C\UID8C267D71_XXXX_MOC_B0

                Get-ItemProperty "HKLM\SYSTEM\CurrentControlSet\Enum\" + $FPR_InstanceID + "\Device Parameters\WinBio\Configurations where DeviceInstancePath\$FPR_InstanceID"

                Use this script to check if a device is ESS-capable.


.DESCRIPTION
                This script checks if a device is ESS-capable. It checks Event-Viewer events
.EXAMPLE
                Run it manually on a local device 
                !!!!  much more testing is required !!!!  if you intend to use it a an Intune detection script to check if a device is ESS-capable
.NOTES
                Nicklas Ahlberg:  initial development and explanaition         https://www.rockenroll.tech/2025/01/21/windows-hello-enhanced-sign-in-security/
                Nicklas Ahlberg:  basic scripts from                           https://github.com/NicklasAhlberg/Intune/tree/main/Remediations/WHfB

                Oliver D.:        2026-Feb-13: several steps re-used and several improvents added
#>

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
<#
     https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/winbio_ioctl/ns-winbio_ioctl-_winbio_sensor_attributes
            WINBIO_SENSOR_ATTRIBUTES structure (winbio_ioctl.h)
    
     https://learn.microsoft.com/en-us/answers/questions/4027263/facial-recognition-in-windows-hello-stopped-workin
    
            WINBIO_E_SENSOR_UNAVAILABLE 0x80098034	       A private pool cannot be created because one or more biometric units are not available.
    
    
     https://learn.microsoft.com/en-us/windows/win32/secbiomet/client-error-codes
    
            WINBIO_E_DEVICE_FAILURE  0x80098036          "The operation failed with error 0x80098036" -> A biometric sensor has failed.
    
        This error indicates that a biometric sensor (fingerprint reader or facial recognition camera) 
        has failed or cannot communicate with the Windows Hello service. 
    
    
     https://learn.microsoft.com/en-us/answers/questions/4027263/facial-recognition-in-windows-hello-stopped-workin
   
            WINBIO_E_INSECURE_SENSOR 0x80098057	          "The operation failed with error: 0x80098057"  -> The biometric sensor does not support a secure hardware data path.
    
#>

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
    param ( [Array]$arrWinEvents , [string]$SearchString, [Switch]$MyDebug)

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

Function Reduce-WinEvents__MessageContent_by_ID
    {
    param ( [Array]$arrWinEvents , [Int]$EventID , [Switch]$MyDebug)
    if ( $Null -eq $arrWinEvents )         
        {
        if ( $MyDebug ) 
            { Write-Host "WinEvents_Reduce_MessageContent() - paramter 'arrWinEvents' is NULL / EMPTY - returning NULL" -ForegroundColor Red 
            }
        Return $NULL
        }
    ForEach ( $Event in $arrWinEvents)
        {
        Switch ( $EventID )
            {
            1105    { 
                    Write-Host "1105 whether a biometric device (sensor) is 'properly loaded and initialized'   or   'NOT'" 
                    
                    $DeleteMeFromMessage = 'The Windows Biometric Service failed to initialize an adapter binary: '
                    $arrWinEvents = Remove-WinEvents__Message_StringToDelete -arrWinEvents $arrWinEvents -StringToDelete $DeleteMeFromMessage 
                      
                    $DeleteMeFromMessage = "The Windows Biometric Service completed a privileged vendor-specific operation for sensor: "
                    $arrWinEvents = Remove-WinEvents__Message_StringToDelete -arrWinEvents $arrWinEvents -StringToDelete $DeleteMeFromMessage 

                    $DeleteMeFromMessage = "The module's ""Sensor Adapter"""
                    $arrWinEvents = Remove-WinEvents__Message_StringToDelete -arrWinEvents $arrWinEvents -StringToDelete $DeleteMeFromMessage

                    $DeleteMeFromMessage = 'routine '
                    $arrWinEvents = Remove-WinEvents__Message_StringToDelete -arrWinEvents $arrWinEvents -StringToDelete $DeleteMeFromMessage 

                    $DeleteMeFromMessage = "See the ""Details"" pane for information about the failing configuration."
                    $arrWinEvents = Remove-WinEvents__Message_StringToDelete -arrWinEvents $arrWinEvents -StringToDelete $DeleteMeFromMessage 
                    }
            1108    { 
                    Write-Host "1108 ... created a Biometric Unit for sensor ..."   
                    $DeleteMeFromMessage = 'The Windows Biometric Service successfully created a Biometric Unit for sensor: '   # EN-US
                    $arrWinEvents = Remove-WinEvents__Message_StringToDelete -arrWinEvents $arrWinEvents -StringToDelete $DeleteMeFromMessage 

                    
                    $DeleteMeFromMessage = 'Der Windows-Biometriedienst hat erfolgreich eine Biometrie-Einheit für Sensor '   # DE-DE
                    $arrWinEvents = Remove-WinEvents__Message_StringToDelete -arrWinEvents $arrWinEvents -StringToDelete $DeleteMeFromMessage 

                    $DeleteMeFromMessage = "See the ""Details"" pane for additional information about the sensor's new configuration."
                    $arrWinEvents = Remove-WinEvents__Message_StringToDelete -arrWinEvents $arrWinEvents -StringToDelete $DeleteMeFromMessage 
                    
                    $DeleteMeFromMessage = "Im Detailbereich finden Sie weitere Informationen zur neuen Sensorkonfiguration."
                    $arrWinEvents = Remove-WinEvents__Message_StringToDelete -arrWinEvents $arrWinEvents -StringToDelete $DeleteMeFromMessage 
                    
                    }
            1109    { 
                    Write-Host "1109 ... failed to configure a sensor ... / ... operation failed with error ....  "   
                    $DeleteMeFromMessage = 'The Windows Biometric Service failed to configure a Biometric Unit for sensor: '
                    $arrWinEvents = Remove-WinEvents__Message_StringToDelete -arrWinEvents $arrWinEvents -StringToDelete $DeleteMeFromMessage 

                    $DeleteMeFromMessage = "See the ""Details"" pane for information about the failing configuration."
                    $arrWinEvents = Remove-WinEvents__Message_StringToDelete -arrWinEvents $arrWinEvents -StringToDelete $DeleteMeFromMessage 
                    }
            1116    { 
                    Write-Host "1116 The Windows Biometric Service's ESS state configuration:"                 
                    # nothing to shorten
                    }
            1601    { 
                    Write-Host "1601 The Windows Biometric Service successfully started its secure component."                 
                    #
                    # nothing to shorten
                    #
                    # $DeleteMeFromMessage = 'The Windows Biometric Service successfully started its secure component.'
                    # $arrWinEvents = Remove-WinEvents__Message_StringToDelete -arrWinEvents $arrWinEvents -StringToDelete $DeleteMeFromMessage 
                    }
            1605    { 
                    Write-Host '1605 The Windows Biometric Service successfully started its secure component.'             
                    #
                    # nothing to shorten
                    #
                    # $DeleteMeFromMessage = 'The Windows Biometric Service successfully started its secure component.'
                    # $arrWinEvents = Remove-WinEvents__Message_StringToDelete -arrWinEvents $arrWinEvents -StringToDelete $DeleteMeFromMessage 
                    }
            1606    { 
                    Write-Host '1606 ..... never had that failure   .... examples required'             
                    #
                    # nothing to shorten
                    #
                    $DeleteMeFromMessage = 'The Windows Biometric Service successfully started its secure component.'
                    $DeleteMeFromMessage = 'Die sichere Komponente des Windows-Biometriediensts wurde erfolgreich gestartet.'
                    # $WinEvents_Biometric1606_All = Remove-WinEvents__Message_StringToDelete -arrWinEvents $WinEvents_Biometric1606_All -StringToDelete $DeleteMeFromMessage 
                    }
            1607    { 
                    Write-Host '1607 ..... never had that failure   .... examples required'             
                    #
                    # nothing to shorten
                    #
                    }
            1608    { 
                    Write-Host '1608 ..... never had that failure   .... examples required'             
                    #
                    # nothing to shorten
                    #
                    }

            Default { Write-Host "Unknown EventID '$EventID'" }
            }   # END    Switch ( $EventID )
        } # END  ForEach $Event
    return $arrWinEvents
    }


clear-Host

#########################################################################
#
# collect Windows Events - reduce Evt-Msg content from MS-'Standard-Phrases'
#
#########################################################################

$WinEvents_Biometric_All = @()

$Today = (Get-Date).Date

# $EventList = (Get-WinEvent -FilterHashtable @{ Logname = 'system'; Id = $1074  } -MaxEvents 10 -ErrorAction silentlyContinue)
$WinEvents_Reboot_ShutDown   = Get-EventViewer_WinEvents__By_LogName_and_ID -LogPath "System" -EventID 1074
$WinEvents_Biometric_All += $WinEvents_Reboot_ShutDown  | Where-Object { $_.TimeCreated -ge $Today }

$AllBioMetricEventIDs = (Get-WinEvent -FilterHashtable @{ProviderName='microsoft-windows-Biometrics'}  -ErrorAction SilentlyContinue) | select ID -Unique | sort ID 
$arrIDs = "'" + ($AllBioMetricEventIDs.ID  -Join "','" ) + "'"
$arrIDs 
# on a Hypper-V   =>   Id =  1108,                1116,  1600,  1601
# on a DELLPC     =>   Id = '1105','1108','1109',              '1601'
$Today = (Get-Date).Date
    
ForEach ( $ID in $AllBioMetricEventIDs)
    {
    $WinEvents_Biometric_ID   = Get-EventViewer_WinEvents__By_LogName_and_ID -LogPath "Microsoft-Windows-Biometrics/Operational" -EventID $($ID.ID)
    $WinEvents_Biometric_ID   = $WinEvents_Biometric_ID | Where-Object { $_.TimeCreated -ge $Today }

    # remove standard strings like "For more details look at https:/..." - any MS-'Standard-Phrase'
    $WinEvents_Biometric_ID   = Reduce-WinEvents__MessageContent_by_ID -arrWinEvents $WinEvents_Biometric_ID -EventID $($ID.ID)

    # replace SubSTrings for better readibilty
    # --------------------------------------------------
    #  ID 1105
    $SearchText =     " initialization failed with error: 0x80098036"
    $NewText    = "`r`nInitialization error: 0x80098036 - A biometric sensor has failed or cannot communicate with the Windows Hello service."
    ForEach ( $Event in $WinEvents_Biometric_ID)
        {
        if ( $Event.Message -like "*$SearchText*"  )
            {
            $Event.Message = ($Event.Message).Replace($SearchText, $NewText)
            }
        }
    # --------------------------------------------------
    #  ID 1108
    $SearchText =     "The sensor's mode is ""Advanced,"" its pool-type is ""System,"" and it's isolated in a ""Virtual Secure Mode"" process."
    $NewText    = "`r`nThe sensor's mode is ""Advanced,"" its pool-type is ""System,"" and it's isolated in a ""Virtual Secure Mode"" process."
    ForEach ( $Event in $WinEvents_Biometric_ID)
        {
        if ( $Event.Message -like "*$SearchText*"  )
            {
            $Event.Message = ($Event.Message).Replace($SearchText, $NewText)
            }
        }

     #  ID 1108
    $SearchText =     "Der Sensor befindet sich im Modus ""Advanced"". Der Pooltyp des Sensors lautet ""System"", und er ist in einem Virtual Secure Mode-Prozess isoliert."
    $NewText    = "`r`nDer Sensor befindet sich im Modus ""Advanced"". Der Pooltyp des Sensors lautet ""System"", und er ist in einem Virtual Secure Mode-Prozess isoliert."
    ForEach ( $Event in $WinEvents_Biometric_ID)
        {
        if ( $Event.Message -like "*$SearchText*"  )
            {
            $Event.Message = ($Event.Message).Replace($SearchText, $NewText)
            }
        }

    # --------------------------------------------------
    #  ID 1108
    $SearchText =     "The sensor's mode is ""Basic,"" its pool-type is ""System,"" and it's isolated in a ""Local System"" process."
    $NewText    = "`r`nThe sensor's mode is ""Basic,"" its pool-type is ""System,"" and it's isolated in a ""Local System"" process."
    ForEach ( $Event in $WinEvents_Biometric_ID)
        {
        if ( $Event.Message -like "*$SearchText*"  )
            {
            $Event.Message = ($Event.Message).Replace($SearchText, $NewText)
            }
        }
    # --------------------------------------------------
    #  ID 1109
    $SearchText =     "The operation failed with error: 0x80098036"
    $NewText    = "`r`nThe operation failed with error: 0x80098036 - A biometric sensor has failed or cannot communicate with the Windows Hello service."
    ForEach ( $Event in $WinEvents_Biometric_ID)
        {
        if ( $Event.Message -like "*$SearchText*"  )
            {
            $Event.Message = ($Event.Message).Replace($SearchText, $NewText)
            }
        }
    # --------------------------------------------------
    #  ID 1109
    $SearchText =     "The operation failed with error: 0x80098057"
    $NewText    = "`r`nThe operation failed with error: 0x80098057 - The biometric sensor does not support a secure hardware data path."
    ForEach ( $Event in $WinEvents_Biometric_ID)
        {
        if ( $Event.Message -like "*$SearchText*"  )
            {
            $Event.Message = ($Event.Message).Replace($SearchText, $NewText)
            }
        }
   
    $WinEvents_Biometric_All += $WinEvents_Biometric_ID
    }

$WinEvents_Biometric_All = $WinEvents_Biometric_All  | Sort TimeCreated -Descending
# $WinEvents_Biometric_All | ft -wrap



#########################################################################
#
# Summary   Windows Events
#
#########################################################################

Write-Host "`r`n==========================================================================="
Write-Host "===================== filtered - only from today =========================="

$WinEvents_Biometric_All | ft -wrap | Out-String |Write-Host

# -------------------------------------------------------
#   filter by sensor's mode   "Basic"
# -------------------------------------------------------
$SearchText = "The sensor's mode is ""Basic,"" its pool-type is ""System,"" and it's isolated in a ""Local System"" process."
$WinEvents_Biometric_Sensor_Basic = Query-WinEvents__Message_match_SearchString -arrWinEvents $WinEvents_Biometric_All -SearchString $SearchText
if ( $WinEvents_Biometric_Sensor_Basic )
    {
    Write-Host "==========================================================================="
    Write-Host "=============== filtered by 'BASIC' from today ============================"
    Write-Host $SearchText
    # $WinEvents_Biometric_Sensor_Basic = Remove-WinEvents__Message_StringToDelete -arrWinEvents $WinEvents_Biometric_Sensor_Basic -StringToDelete $SearchText
    $WinEvents_Biometric_Sensor_Basic  | Sort TimeCreated -Descending | FT -Wrap | Out-String | Write-Host
    }

# -------------------------------------------------------
#   filter by sensor's mode   "Advanced"
# -------------------------------------------------------
$SearchText = "The sensor's mode is ""Advanced,"" its pool-type is ""System,"" and it's isolated in a ""Virtual Secure Mode"" process."
$WinEvents_Biometric_Sensor_Advanced = Query-WinEvents__Message_match_SearchString -arrWinEvents $WinEvents_Biometric_All -SearchString $SearchText
if ( $WinEvents_Biometric_Sensor_Advanced )
    {
    Write-Host "==========================================================================="
    Write-Host "============= filtered by 'Advanced'  from today ==========================="
    Write-Host $SearchText
    # $WinEvents_Biometric_Sensor_Advanced = Remove-WinEvents__Message_StringToDelete -arrWinEvents $WinEvents_Biometric_Sensor_Advanced -StringToDelete $SearchText
    $WinEvents_Biometric_Sensor_Advanced  | Sort TimeCreated -Descending | FT -Wrap | Out-String | Write-Host
    }


# -------------------------------------------------------
#   filter by InstanceID / DeviceName
# -------------------------------------------------------
# Get EventViewer Biometrics-log - all ID=1108 events containing "Virtual Secure Mode"
$SearchText = "(ROOT\WINDOWSHELLOFACESOFTWAREDRIVER\0000)"
$WinEvents_Biometric_InstanceID = Query-WinEvents__Message_match_SearchString -arrWinEvents $WinEvents_Biometric_All -SearchString $SearchText
if     ( $WinEvents_Biometric_InstanceID )
    {
    Write-Host "==========================================================================="
    Write-Host "================== filtered by InstanceID  from today ======================="
    Write-Host $SearchText
    $WinEvents_Biometric_InstanceID | Sort TimeCreated -Descending | FT -Wrap | Out-String |Write-Host
    }
elseif ( $WinEvents_Biometric_InstanceID -eq $Null )
    {
    $SearchText = "Windows Hello Face Virtual Software Device"
    Write-Host "==========================================================================="
    Write-Host "================= filtered by DeviceName from today ======================="
    Write-Host $SearchText
    $WinEvents_Biometric_DeviceName = Query-WinEvents__Message_match_SearchString -arrWinEvents $WinEvents_Biometric_All -SearchString $SearchText
    $WinEvents_Biometric_DeviceName | Sort TimeCreated -Descending | FT -Wrap | Out-String |Write-Host
    }


$SearchText = "Virtual Secure Mode"
Write-Host "==========================================================================="
Write-Host "=========== filtered by '$SearchText' from today =================="
$WinEvents_Biometric_Secure = Query-WinEvents__Message_match_SearchString -arrWinEvents $WinEvents_Biometric_All -SearchString $SearchText
$WinEvents_Biometric_Secure | Sort TimeCreated -Descending | FT -Wrap | Out-String |Write-Host


if ( $WinEvents_Biometric_Secure )     { Write-Output "'Windows Hello ESS' is     working in 'Virtual Secure Mode'"                 }
else                                   { Write-output "'Windows Hello ESS' is NOT working in 'Virtual Secure Mode' - please verify" }

return


#
#     Only comments and information after this line
#
#########################################################################
#
# SENSOR:  'Analog NUI Voice Virtual Sensor (\Voice\Virtual Sensors\{F25AB4A2-593A-4A89-B9FF-8144BEA81E15})'
#
# The "Analog NUI Voice Virtual Sensor" is a component of the Windows Biometric Service (WBS), 
# often appearing in system logs or device management, which acts as a software-based (virtual) sensor for voice input. 
# It enables biometric authentication and Natural User Interface (NUI) features in Windows, 
# allowing user voice recognition without a physical, dedicated analog microphone sensor. 

#########################################################################
# Get EventViewer Biometrics-log - all ID=1004 
#
#      "The Windows Biometric Service successfully identified <hostname>\<username> (SID) using sensor: 
#      VeriMark DT Fingerprint Key (USB\VID_047D&PID_00F2&MI_01\7&163AA6B8&0&0001)."
#
#########################################################################
# Get EventViewer Biometrics-log - all ID=1105
#    
#     'The Windows Biometric Service failed to initialize an adapter binary: '
#
#     See the ""Details"" pane for information about the failing configuration.
#
#########################################################################
# Get EventViewer Biometrics-log - all ID=1018   
#
#########################################################################
# Get EventViewer Biometrics-log - all ID=1019   
#
#     "The Windows Biometric Service completed a privileged vendor-specific operation for sensor: 
#      Facial Recognition (Windows Hello) Software Device (ROOT\WINDOWSHELLOFACESOFTWAREDRIVER\0000).
#      The command was directed to the biometric unit's 'Sensor Adapter' component."
#
#########################################################################
# Get EventViewer Biometrics-log - all ID=1104   
#
#      Indicates a successful biometric scan.
#
#########################################################################
# Get EventViewer Biometrics-log - all ID=1108
# 
#     Confirms whether a biometric device (sensor) is properly loaded and initialized.
#     Confirms the sensor (fingerprint or camera) is operating correctly. 
#     If Enhanced Sign-in Security (ESS) is enabled, the device is isolated in a "Virtual Secure Mode" process. 
# 
#        Goodix MOC Fingerprint (USB\VID_27C6&PID_634C\UID8C267D71_XXXX_MOC_B0)
#        The sensor's mode is "Advanced," its pool-type is "System," and it's isolated in a "Virtual Secure Mode" process.                                                            
#
#########################################################################
# Get EventViewer Biometrics-log - all ID=1109
#
#########################################################################
# Get EventViewer Biometrics-log - all ID=1601
#
#       "The Windows Biometric Service successfully started its secure component."    
#
#########################################################################
# Get EventViewer Biometrics-log - all ID=1605
#
#       "The Windows Biometric Service secure component successfully authorized user (domain)<user>"
#
#########################################################################
# Get EventViewer Biometrics-log - all ID=1606 
#
#        ..... never had that failure   .... examples required
#
#########################################################################
# Get EventViewer Biometrics-log - all ID=1607 
#
#        ..... never had that failure   .... examples required
#
#########################################################################
# Get EventViewer Biometrics-log - all ID=1608 
#
#        ..... never had that failure   .... examples required
#
#########################################################################