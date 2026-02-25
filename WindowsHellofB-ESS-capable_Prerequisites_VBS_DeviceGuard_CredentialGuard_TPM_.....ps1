<#
    Get-ItemProperty -Path "HKLM:SOFTWARE\Microsoft\Windows\CurrentVersion\WinBio" 

    Dell Corp PC                                     Hyper V

    SecureBioAvailabilityInCensus   : 1        -    SecureBioAvailabilityInCensus   : 13
    ESSCapableOnLastStart           : 1        -    ESSCapableOnLastStart           : 0
    PeripheralsWithESSPreviousValue : 0        -    PeripheralsWithESSPreviousValue : 0
                                                    NonVsmStateUpgradeFlow          : 1
                                                    FaceBioUnitConfigured           : 0
                                                    EnableESSPreviousValue          : 1

    Get-ItemProperty -Path "HKLM:SOFTWARE\Microsoft\Windows\CurrentVersion\WinBio\SensorInfo"
    AvailableFactors : 12                           AvailableFactors : 4


#>

<#
    # run as admin
    Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard

                                                    Hyper-V            Prec 5690

    AvailableSecurityProperties                  : {1, 2, 3, 5...}     {1, 2, 3, 4...}
    CodeIntegrityPolicyEnforcementStatus         : 2                   2
    InstanceIdentifier                           : 4ff40742-2649-41b8-bdd1-e80fad1cce80
    RequiredSecurityProperties                   : {0}                 {0}
    SecurityFeaturesEnabled                      : {0}                 {0}
    SecurityServicesConfigured                   : {2}                 {2}          (should include 1 for VBS, 2 for HVCI)
    SecurityServicesRunning                      : {2}                 {1, 2, 7}    (should include 1 at minimum)    0 = No services running, 1 = Credential Guard is running,  2 = HVCI is running  
    SmmIsolationLevel                            : 0                   0
    UsermodeCodeIntegrityPolicyEnforcementStatus : 0                   2
    Version                                      : 1.0                 1.0
    VirtualizationBasedSecurityStatus            : 2                   2            (should be 2 => enabled and running)
    VirtualMachineIsolation                      : False               False
    VirtualMachineIsolationProperties            : {0}                 {0}


    
    AvailableSecurityProperties	- relevant security properties for Device Guard.	
        0. If present, no relevant properties exist on the device.
        1. If present, hypervisor support is available.
        2. If present, Secure Boot is available.
        3. If present, DMA protection is available.
        4. If present, Secure Memory Overwrite is available.
        5. If present, NX protections are available.
        6. If present, SMM mitigations are available.
        7. If present, MBEC/GMET is available.
        8. If present, APIC virtualization is available.
    
    
    RequiredSecurityProperties	This field describes the required security properties to enable virtualization-based security.	
        0. Nothing is required.
        1. If present, hypervisor support is needed.
        2. If present, Secure Boot is needed.
        3. If present, DMA protection is needed.
        4. If present, Secure Memory Overwrite is needed.
        5. If present, NX protections are needed.
        6. If present, SMM mitigations are needed.
        7. If present, MBEC/GMET is needed.

    SecurityServicesConfigured	This field indicates whether the Credential Guard or HVCI service has been configured.	
        0. No services configured.
        1. If present, Credential Guard is configured.
        2. If present, HVCI is configured.
        3. If present, System Guard Secure Launch is configured.
        4. If present, SMM Firmware Measurement is configured.

    SecurityServicesRunning	This field indicates whether the Credential Guard or HVCI service is running.	
        0. No services running.
        1. If present, Credential Guard is running.
        2. If present, HVCI is running.
        3. If present, System Guard Secure Launch is running.
        4. If present, SMM Firmware Measurement is running.

    VirtualizationBasedSecurityStatus	This field indicates whether VBS is enabled and running.	
        0. VBS is not enabled.
        1. VBS is enabled but not running.
        2. VBS is enabled and running.

#>



# Get-WmiObject -Namespace root\cimv2\security\microsofttpm -Class Win32_Tpm

# Get-PnpDevice -FriendlyName "*biometric*" | Select-Object FriendlyName, Class, Status

# remove (hidden) drivers
#     pnputil /enum-drivers > drivers.txt  
#     notepad drivers.txt      - search for related drivers
#     pnputil /delete-driver oem##.inf /uninstall /force  

