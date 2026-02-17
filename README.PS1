Windows Hello Enhanced Sign-in Security ( ESS )


# https://learn.microsoft.com/en-us/windows-hardware/design/device-experiences/windows-hello-enhanced-sign-in-security#system-requirements

# Windows Hello Enhanced Sign-in Security ( ESS )
# - The enablement of ESS is dependent on specialized hardware, drivers, and firmware pre-installed on the system. 
# - ESS is NOT supported for external fingerprint sensors or external camera modules.
#
# Requirements
# --------------
# Virtualization Based Security (VBS) 
#            MsInfo32.exe -> System Information > System Summary -> Virtualization Based Security 
# Trusted Platform Module 2.0 
# Biometric sensor hardware that supports ESS ( with match on sensor capabilities. )
# Biometric sensor drivers compatible with ESS
# Device firmware (BIOS) with a Secure Devices (SDEV) ACPI table configured by the device manufacturer for the included biometric hardware
#   e.g.  Most brands has a specific setting that must be enable. “Enhanced Windows Biometric Security”


Unknown   The Windows Biometric Credential Manager failed to remove a credential.      -   The operation failed with error: 0x80098031.
- Event-OD ????  These errors suggest a problem with the biometric service, possibly related to drivers, system configuration, biometric data, or even hardware.
---- launch Device Manager. 
----    Locate your biometric-related driver, right-click it, and select Uninstall. 
---- Action > Scan for hardware changes. 
----    Windows will search for and install an appropriate driver if connected to the internet. 
----    Restart your device after installation.  
---- services.msc ( Services manager ). 
----      Locate the Windows Biometric Service, right-click it, and select Stop.
----  Explorer - C:\Windows\System32\WinBioDatabase
----      find the data files there, and delete them. (If they cannot be deleted, rename them first and then delete.)
----  Restart your device. Follow the previous steps to start the Windows Biometric Service again.


# Face biometric sensor
# --------------
# DevMgmt.Msc -> Universal Serial Bus controllers -> eXtensible Host Controller
#    for each
#           Properties  - Details - One of the devices should show the   CM_DEVCAP_SECUREDEVICE    capability.
# DevMgmt.Msc -> Camera
#           Properties  - Details - One of the devices should show the   CM_DEVCAP_SECUREDEVICE    capability.
#   
#
#   Get-PnpDevice  | where-object { ($_.Status -eq 'OK') }  | Select Class,Manufacturer,FriendlyName,InstanceId | Sort FriendlyName,Class,Manufacturer
#
#   $CameraInstanceIDs = (Get-PnpDevice  | where-object { ($_.Class -eq 'Camera') -and ($_.Status -eq 'OK') } | select InstanceId).InstanceId
#

<#
    Get-PnpDevice -PresentOnly -Class Camera | Get-PnpDeviceProperty -KeyName DEVPKEY_Device_Capabilities | Select DeviceID,KeyName,Data,key  #,InstanceId

    DeviceID                                      KeyName                     Data key                                      
    --------                                      -------                     ---- ---                                      
    USB\VID_0C45&PID_636B&MI_00\C&315A9F63&0&0000 DEVPKEY_Device_Capabilities  164 {A45C254E-DF1C-4EFD-8020-67D146A850E0} 17
    DISPLAY\INT3480\4&130D02DC&1&UID144512        DEVPKEY_Device_Capabilities  224 {A45C254E-DF1C-4EFD-8020-67D146A850E0} 17
#>


<#
DEVPKEY_Device_Capabilities   ( *PDEVICE_CAPABILITIES )
The value stored as DEVPKEY_Device_Capabilities is a bitfield mapping to the capabilities defined in Cfgmgr32.h 
          Windows 10  - 10.0.16299.0  (  Fall Creators Update or Version 1709 )
          https://github.com/tpn/winsdk-10/blob/master/Include/10.0.16299.0/um/cfgmgr32.h
- easiest way to parse the value is to define an enum type with the [Flags()] attribute then convert the value to that:

more info
        https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ns-wdm-_device_capabilities

[Flags()]
enum DeviceCapabilities 
    {
      LOCKSUPPORTED      = 0x0001
      EJECTSUPPORTED     = 0x0002
      REMOVABLE          = 0x0004
      DOCKDEVICE         = 0x0008
      UNIQUEID           = 0x0010
      SILENTINSTALL      = 0x0020
      RAWDEVICEOK        = 0x0040
      SURPRISEREMOVALOK  = 0x0080
      HARDWAREDISABLED   = 0x0100
      NONDYNAMIC         = 0x0200
      SECUREDEVICE       = 0x0400
    }
Get-PnpDevice -Class Camera -PresentOnly |Select FriendlyName,InstanceId,@{Name='Capabilities';Expression={($_ |Get-PnpDeviceProperty -KeyName DEVPKEY_Device_Capabilities).Data -as [DeviceCapabilities]}}

=>
    FriendlyName                 InstanceId                                                                     Capabilities
    ------------                 ----------                                                                     ------------
    USB 2.0 Camera               USB\VID_0C45&PID_636B&MI_00\C&315A9F63&0&0000   REMOVABLE, SILENTINSTALL, SURPRISEREMOVALOK
    Intel(R) MTL AVStream Camera DISPLAY\INT3480\4&130D02DC&1&UID144512        SILENTINSTALL, RAWDEVICEOK, SURPRISEREMOVALOK

#>



# Fingerprint biometric sensor
# DevMgmt.Msc -> Biometric devices -> Fingerprint
#           Properties  - Details - [Device instance path].  ( USB\VID_413C&PID_B06E\DF49E5AA0FC05665     )
# reg query HKLM\SYSTEM\CurrentControlSet\Enum\[Device instance path]\Device Parameters\WinBio\Configurations     /v SecureFingerprint 
#       should return   1    

# ESS is enabled ?
# a)
# Windows Security application  -> Device Security 
#   -> if "Enhanced Sign-in Security" is visible 
#          => enabled
#               => hardware capability of the system
#               =>  or "Unavailable due to incompatible hardware"   -> no capable sensors deteced
# b)
# Windows > Settings > Accounts > Sign-in options 
#     Additional settings > Sign in with an external camera or fingerprint reader  - temporarily Enabel/Disable ESS
#                            if ESS is enabled and you can't use    external    peripherals to sign in. 
#                           

# ESS Win-Events
# Event Viewer -> Applications and Services Logs -> Microsoft -> Windows -> Biometrics -> Operational.
#
#    wevtutil el | find /i "Biometric"
#          Microsoft-Windows-Biometrics/Analytic
#          Microsoft-Windows-Biometrics/Operational
#
#
# - event ID 1108 for the corresponding sensor is loaded properly.
#    Get-WinEvent -FilterHashtable @{ProviderName='microsoft-windows-Biometrics'; Id=1108}  -ErrorAction SilentlyContinue
#
#    cameras are described using Windows Hello Face Software Device
#
#        ->  .... Facial Recognition (Windows Hello) Software Device (ROOT\WINDOWSHELLOFACESOFTWAREDRIVER\0000)....
#
#    fingerprint devices are described using the device's specific module and device ID.
#        ->  device Manager -> Biometric Devices > [Fingerprint Module] > Properties > Details > Device Instance Path.
#


Get-WinEvent -FilterHashtable @{ProviderName='microsoft-windows-Biometrics'}  -ErrorAction SilentlyContinue `
    | select ID -Unique `
    | sort ID
    
    # on my test PC      =>      Id = 1105,1108,1109,1601

Services.MSC
        Services.msc - 'Windows Biometric Service' - 'Startup type' change to 'Automatic'
        
        sc config WbioSrvc start= Demand
        sc config WbioSrvc start= Auto
GPEdit.MSC
    Computer Configuration > Administrative Templates > Windows Components > Biometrics
    - This policy setting allows or prevents the Windows Biometric Service to run on this computer.
    - If you enable or do not configure this policy setting, 
    - the Windows Biometric Service is available, and 
    - users can run applications that use biometrics on Windows. 
    If you want to enable the ability to log on with biometrics, you must also configure the "Allow users to log on using biometrics" policy setting.
    If you disable this policy setting, the Windows Biometric Service is unavailable, and users cannot use any biometric feature in Windows.

    e.g.  HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System\AllowDomainPINLogon


1020 - The Windows Biometric Service cannot complete a request because biometric operations are disabled by current system policy. 
 
1600 - The Windows Biometric Service failed to start its secure component.Reason for unavailability: 12.The operation failed with error: 0x80070032.     

		Um den Fehler 0x80070032 zu beheben, sollten Sie zunächst versuchen, erneut eine PIN zu erstellen, sich abzumelden und das Gerät neu zu starten. 

		Re-enroll your PIN:
		Re-enroll your Facial Recognition


Windows Hello Face Virtual Software Device (\Bootstrap\Virtual Sensors\{0527b250-7514-4321-8b68-41c65f956998}).

Biometric Service failed to configure a Biometric Unit for sensor: Windows Hello Face Virtual Software Device (\Bootstrap\Virtual Sensors\{0527b250-7514-4321-8b68-41c65f956998}).
The operation failed with error: 0x80004001

The operation failed with error: 0x80070032.
Configure Automatic Startup of Biometric-Service ( Services.Msc )

Biometric Service successfully created a Biometric Unit for sensor: Control Vault w/ Fingerprint Touch Sensor (CVUSBDRV\CV3_WBF_PROVIDER_TOUCH\6&C3AC727&0&513)
The sensor's mode is "Advanced," its pool-type is "System," and it's isolated in a "Local System" process.


 the device driver ((C:\windows\system32\winBioplugins\ *.dll )) is signed with a certificate that expired on 26 - 27 september , depending on your timezone.

enabled Windows Hello for business Intune 
----------
July 2024, the following Intune profiles for 'identity protection' and 'account protection' were deprecated and replaced by a new consolidated profile named 'Account protection'. 
This newer profile is found in the account protection policy node of endpoint security,
----------
Intune -> Device -> enrollment   -> Windows hello for business
Identity protection (previously)
Intune -> Devices > Configuration > Create > New Policy > Windows 10 and later > Templates > Identity Protection


In addition to Account protection profiles, Intune supports the following options to manage settings for Windows Hello for Business:

During device enrollment: Configure tenant-wide policy that applies Windows Hello settings to devices at the time the device enrolls with Intune.
-- Configure Windows Hello for Business on devices when they enroll with Intune
-- https://learn.microsoft.com/en-us/intune/intune-service/protect/windows-hello

Security baselines: Some settings for Windows Hello can be managed through Intune's security baselines, 
like the baselines for Microsoft Defender for Endpoint security or Security Baseline for Windows 10 and later.
-- Use security baselines to help secure Windows devices you manage with Microsoft Intune
-- https://learn.microsoft.com/en-us/intune/intune-service/protect/security-baselines
-- https://learn.microsoft.com/en-us/intune/intune-service/protect/security-baseline-settings-mdm-all?pivots=mdm-24h2#windows-hello-for-business

Settings catalog: The settings from endpoint security Account protection profiles are available in the Intune settings catalog.
-- Use the Intune settings catalog to configure settings
-- https://learn.microsoft.com/en-us/intune/intune-service/configuration/settings-catalog?tabs=sc-search-filter%2Csc-reporting


https://learn.microsoft.com/en-us/windows/security/identity-protection/hello-for-business/configure?source=recommendations#configure-windows-hello-for-business-using-microsoft-intune

reg query HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Policies\PassportForWork\
	HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Policies\PassportForWork\Biometrics
	HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Policies\PassportForWork\{TenantId}
	HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Policies\PassportForWork\SecurityKey

HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Policies\PassportForWork\Biometrics        UseBiometrics    REG_DWORD    0x0


GpEdit
Computer > Administrative Templates > Windows Components > Windows Hello For Business  ---- Use Biometrics --- enabled
Computer > Administrative Templates > Windows Components > Windows Hello For Business  ---- Use Windows Hello For Business --- enabled



Telemetry 
HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DataCollection      AllowTelemetry   1.
Services.MSC - "Connected User Experiences and Telemetry"                 Start-up type    Automatic 




