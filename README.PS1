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



