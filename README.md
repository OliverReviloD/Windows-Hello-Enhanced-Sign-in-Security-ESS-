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
