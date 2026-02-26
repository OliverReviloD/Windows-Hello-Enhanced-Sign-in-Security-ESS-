#
# services.mmc
#
#         Stopped  WbioSrvc           Windows Biometric Service 
# 
# Startup Type: Defaults to "Automatic".
# Dependencies: Requires RPC, Credential Manager, and Windows Driver Foundation to function.
# Disabling:    While it can be disabled, it will break Windows Hello biometric sign-in.
#
$ServiceName = 'WbioSrvc'
$objBiometricService = get-service -Name $ServiceName
$objBiometricService | select * 
if ($objBiometricService.Status -eq 'Stopped')
    {
    Start-Service -Name $ServiceName -PassThru

    }

$EvtLogName = 'microsoft-windows-Biometrics'
$EvtLogPath = 'Microsoft-Windows-HelloForBusiness/Operational'   # deprecated name  - 
$EvtLogPath = 'microsoft-windows-Biometrics/Operational'

$Today = (Get-Date).date  # starttime = 00:00:00    # | Where {$_.TimeCreated -gt $Today}  
$IDs =  Get-WinEvent -FilterHashtable @{ProviderName=$EvtLogName }  -ErrorAction SilentlyContinue `
  | sort TimeCreated  | select ID  | select ID -Unique `
    
$IDs  

$QueryForId = 1600
$FilterString = "<QueryList><Query><Select Path='$EvtLogPath'>*[System[(EventID=$QueryForId)]]</Select></Query></QueryList>"
Get-WinEvent -FilterXml $FilterString  | ft -Wrap
$Events = Get-WinEvent -FilterXml $FilterString -ErrorAction SilentlyContinue 
  

$Today = (Get-Date).date  # starttime = 00:00:00
$Events = Get-WinEvent -FilterHashtable @{ProviderName=$EvtLogName}  -ErrorAction SilentlyContinue | Where {$_.TimeCreated -gt $Today} | sort TimeCreated
$Events | ft -Wrap

# The operation failed with error: 
#  0x80070032 ----- The request is not supported
#  0x80098031 ----- The Windows Biometric Credential Manager failed to remove a credential 
#  0x8007007E ----- The Windows Biometric Service failed to load an adapter binary: <path/to/my/engineadapter.dll>. The module was not properly signed.
#                => The Windows Biometric Service failed to configure a Biometric Unit for sensor: <name of my device> (<hardware-ID>).
#  0x80098057
#
#
#  Reason 64  or Reason  256 ? :  Your sensor driver was downgraded to a version that’s not HVCI-compliant during fallback.
#

# on a Hyper-V   - Reason for unavailability: 12
# 1600        "The Windows Biometric Service failed to start its secure component. Reason for unavailability: 12. The operation failed with error: 0x80070032. 
#             Google KI: Reason 12  => and related to hardware or driver issues
#
# on Dell Corp PC
# 1600        "The Windows Biometric Service failed to start its secure component. Reason for unavailability: 64. The operation failed with error: 0x80070032
#
#
#
# 1600        "The Windows Biometric Service failed to start its secure component. Reason for unavailability: 256.

<#
    #
    # order of events  ( e.g. after boot ) - Intune PC, only 3rd party external camera and "unconfigured" ( never used, never initialized ) fingerprint reader
    #
    # ------------------------------------
     ( e.g. after boot )
    1601   Biometric Service successfully started its secure component.
    # Facial - Cameras
    1108   Biometric Service successfully created a Biometric Unit for sensor: Windows Hello Face Virtual Software Device (\Bootstrap\Virtual Sensors\{0527b250-7514-4321-8b68-41c65f956998})
    1108   Biometric Service successfully created a Biometric Unit for sensor: Analog NUI Voice Virtual Sensor (\Voice\Virtual Sensors\{F25AB4A2-593A-4A89-B9FF-8144BEA81E15})
    
    # ------------------------------------
    only on a Hyper-V immedeately after 1601 and the 2 above 1108 events
    1116 Biometric Service's ESS state configuration:
        Requires TPM: false
        VBS capable: true
        Non VBS Windows Hello: false
        VBS Windows Hello: false
        Requires VBS Runnig: false
        Requires VBS Encryption keys: false
        Requires enablement: false
        Managed by policy: false
        Non VBS Bio Enrollments: false
        VBS Bio enrollments: false
        ESS face sensor: false
        ESS fpr sensor: false
        Requires isolated process: false
        Blocked non ESS fpr: false
        Blocked non ESS camera: false
        Is device ESS state default: true 
    # ------------------------------------

    1105   Biometric Service failed to initialize an adapter binary: Facial Recognition (Windows Hello) Software Device (ROOT\WINDOWSHELLOFACESOFTWAREDRIVER\0000).The module's "Sensor Adapter" initialization routine failed with error: 0x80098036
    1109   Biometric Service failed to configure a Biometric Unit for sensor: Facial Recognition (Windows Hello) Software Device (ROOT\WINDOWSHELLOFACESOFTWAREDRIVER\0000).The operation failed with error: 0x80098036
    1109   Biometric Service failed to configure a Biometric Unit for sensor: Facial Recognition (Windows Hello) Software Device (ROOT\WINDOWSHELLOFACESOFTWAREDRIVER\0000).The operation failed with error: 0x80098057                                                 
    # Fingerprint
    1108   Biometric Service successfully created a Biometric Unit for sensor: Goodix MOC Fingerprint (USB\VID_27C6&PID_634C\UID8C267D71_XXXX_MOC_B0)

    # ------------------------------------
     ( e.g. after log-On ) ? 10 min later ?   
    1601   Biometric Service successfully started its secure component.  
    1108   Biometric Service successfully created a Biometric Unit for sensor: Windows Hello Face Virtual Software Device (\Bootstrap\Virtual Sensors\{0527b250-7514-4321-8b68-41c65f956998})
    1108   Biometric Service successfully created a Biometric Unit for sensor: Analog NUI Voice Virtual Sensor (\Voice\Virtual Sensors\{F25AB4A2-593A-4A89-B9FF-8144BEA81E15})
    1105   Biometric Service failed to initialize an adapter binary: Facial Recognition (Windows Hello) Software Device (ROOT\WINDOWSHELLOFACESOFTWAREDRIVER\0000).The module's "Sensor Adapter" initialization routine failed with error: 0x80098036
    1109   Biometric Service failed to configure a Biometric Unit for sensor: Facial Recognition (Windows Hello) Software Device (ROOT\WINDOWSHELLOFACESOFTWAREDRIVER\0000).The operation failed with error: 0x80098036
    1109   Biometric Service failed to configure a Biometric Unit for sensor: Facial Recognition (Windows Hello) Software Device (ROOT\WINDOWSHELLOFACESOFTWAREDRIVER\0000).The operation failed with error: 0x80098057

    1108   Biometric Service successfully created a Biometric Unit for sensor: Goodix MOC Fingerprint (USB\VID_27C6&PID_634C\UID8C267D71_XXXX_MOC_B0)

    # ------------------------------------
    And again after another 20 min - identical order of events, like above

    ################################################
    ################################################

    # ? shutdown events ?  01:00:53
    1600   Biometric Service failed to start its secure component.Reason for unavailability: 64.The operation failed with error: 0x80070032
    1103   Biometric Service failed to open sensor: Facial Recognition (Windows Hello) Software Device (ROOT\WINDOWSHELLOFACESOFTWAREDRIVER\0000).The operation failed with error: 0x80070006

    # Boot events      07:28:37
    1601   Biometric Service successfully started its secure component. 
    1108   Biometric Service successfully created a Biometric Unit for sensor: Windows Hello Face Virtual Software Device ...
    1108   Biometric Service successfully created a Biometric Unit for sensor: Analog NUI Voice Virtual Sensor
    1105   Biometric Service failed to initialize an adapter binary: Facial Recognition (Windows Hello) Software Device          ... failed with error: 0x80098036
    1109   Biometric Service failed to configure a Biometric Unit for sensor: Facial Recognition (Windows Hello) Software Device ... failed with error: 0x80098036
    1109   Biometric Service failed to configure a Biometric Unit for sensor: Facial Recognition (Windows Hello) Software Device ... failed with error: 0x80098036
    1108   Biometric Service successfully created a Biometric Unit for sensor: Goodix MOC Fingerprint  

    # log-in via PIN   07:36:25
    1601   Biometric Service successfully started its secure component.                                                                   
    1108   Biometric Service successfully created a Biometric Unit for sensor: Windows Hello Face Virtual Software Device                 
    1108   Biometric Service successfully created a Biometric Unit for sensor: Analog NUI Voice Virtual Sensor 
    1105   Biometric Service failed to initialize an adapter binary: Facial Recognition (Windows Hello) Software Device           ... failed with error: 0x80098036                  
    1109   Biometric Service failed to configure a Biometric Unit for sensor: Facial Recognition (Windows Hello) Software Device  ... failed with error: 0x80098036
    1109   Biometric Service failed to configure a Biometric Unit for sensor: Facial Recognition (Windows Hello) Software Device  ... failed with error: 0x80098057
    1108   Biometric Service successfully created a Biometric Unit for sensor: Goodix MOC Fingerprint                                     
                                                     
    # ? re-log-in ?   or ? automatic ( High-Noon )?  12:00:35
    1601   Biometric Service successfully started its secure component.                                                                   
    1108   Biometric Service successfully created a Biometric Unit for sensor: Windows Hello Face Virtual Software Device                 
    1108   Biometric Service successfully created a Biometric Unit for sensor: Analog NUI Voice Virtual Sensor 
    1105   Biometric Service failed to initialize an adapter binary: Facial Recognition (Windows Hello) Software Device           ... failed with error: 0x80098036                  
    1109   Biometric Service failed to configure a Biometric Unit for sensor: Facial Recognition (Windows Hello) Software Device  ... failed with error: 0x80098036
    1109   Biometric Service failed to configure a Biometric Unit for sensor: Facial Recognition (Windows Hello) Software Device  ... failed with error: 0x80098057
    1108   Biometric Service successfully created a Biometric Unit for sensor: Goodix MOC Fingerprint                                     
    ################################################
    ################################################



#>



Function Clear-WinEvent_LogFile 
    {
    param ( $EvtLogName    = "Microsoft-Windows-Biometrics",
            $EvtLogNameSub = "Operational" )
    
    $EvtLogPath = "$EvtLogName/$EvtLogNameSub"
    $ObjWinEventLog = Get-WinEvent -ListLog * -ErrorAction SilentlyContinue | Where  { $_.LogName -eq $EvtLogPath }
    <#
        LogMode   MaximumSizeInBytes RecordCount LogName                                                                                                                                                                                           
        -------   ------------------ ----------- -------                                                                                                                                                                                           
        Circular             1052672        1004 Microsoft-Windows-Biometrics/Operational        
    #>

    if ( $ObjWinEventLog )
        {
         Write-Host "'$($ObjWinEventLog.LogName) exists "   # => Microsoft-Windows-Biometrics/Operational
         if ($ObjWinEventLog.RecordCount -gt 0 )
             { 
             Write-Host "$($ObjWinEventLog.RecordCount) events detected - starting to clear log $($ObjWinEventLog.LogName)'"
    #
    #Requires -RunAsAdministrator
    #
             [System.Diagnostics.Eventing.Reader.EventLogSession]::GlobalSession.ClearLog( $($ObjWinEventLog.LogName ))
             }
        Get-WinEvent -ListLog * -ErrorAction SilentlyContinue | Where  { $_.LogName -eq $($ObjWinEventLog.LogName) }
        Get-WinEvent -LogName $($ObjWinEventLog.LogName)  -ErrorAction SilentlyContinue

        }
    }

