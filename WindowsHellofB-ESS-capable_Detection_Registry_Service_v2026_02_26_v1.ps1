# HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WbioSrvc
#    Group    REG_SZ    SmartCardGroup
#    Start    REG_DWORD    0x2
#
# HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WbioSrvc\Databases\{GUID 1}
#     BiometricType    REG_DWORD    0x2 (FacialFeatures)      or     0x4 (Voice)     or      0x8 (Fingerprint)      or   0x10 (Iris) 
#
# HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WbioSrvc\Service Providers\Bootstrap 
#     BiometricType    REG_DWORD    0x0
#
# HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WbioSrvc\Service Providers\Bootstrap\Global Configurations
#     ActiveConfiguration    REG_SZ    None
# 
# HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WbioSrvc\Service Providers\Bootstrap\Virtual Sensors\{GUID 1}
#    Capabilities         REG_DWORD    0x80
#    DeviceDescription    REG_SZ    Windows Hello Face Virtual Software Device
#    ModelName            REG_SZ    Windows Hello Face Virtual Sensor
# HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WbioSrvc\Service Providers\Bootstrap\Virtual Sensors\{GUID 1}\Configurations\0
#    DefaultConfiguration    REG_DWORD    0x0
#
# HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WbioSrvc\Service Providers\Bootstrap\Virtual Sensors\{GUID 1}\Configurations\0
#    DatabaseId             REG_SZ    DC576DA6-D676-4A15-906D-C0CEAF949543
#    SensorMode             REG_DWORD    0x1
#    SystemSensor           REG_DWORD    0x1
# 
# HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WbioSrvc\Service Providers\FacialFeatures\Global Configurations
#     ActiveConfiguration    REG_SZ    None
# 
# HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WbioSrvc\Service Providers\Fingerprint\Global Configurations
#     ActiveConfiguration    REG_SZ    None
# 
# HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WbioSrvc\Service Providers\Voice\Global Configurations
#     ActiveConfiguration    REG_SZ    None
# 
# HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WbioSrvc\Service Providers\Voice\Virtual Sensors\{F25AB4A2-593A-4A89-B9FF-8144BEA81E15}
#     Capabilities       REG_DWORD    0x81
#     DeviceDescription  REG_SZ    Analog NUI Voice Virtual Sensor
#     ModelName          REG_SZ    Analog NUI Voice Virtual Sensor
#
#
#     Action (00000001)           : Typically indicates a "start service" action when the trigger conditions are met.
#     GUID                        : Associates the trigger with a specific interface or event, often related to biometric device interfaces.
#    
# HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WbioSrvc\TriggerInfo\0
#    Action     REG_DWORD    0x1
#    Data0      REG_BINARY    430030004500390036003700310045002D0033003300430036002D0034003400330038002D0039003400360034002D003500360042003200450031004200310043003700420034000000
#    DataType0  REG_DWORD    0x2
#    GUID       REG_BINARY    67D190BC70943941A9BABE0BBBF5B74D
#    Type       REG_DWORD    0x6



cls
$WbioSrvc_RootKey                  = "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WbioSrvc"
$WbioSrvc_RootKey                  = "HKLM:SYSTEM\CurrentControlSet\Services\WbioSrvc"
$WbioSrvc_ServiceProviders_RootKey = "$WbioSrvc_RootKey\Service Providers"



$results = Get-Item $WbioSrvc_ServiceProviders_RootKey # | select *
# $results.Name        # HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WbioSrvc\Service Providers
# $results.SubKeyCount # 5
$SubKeys = Get-ChildItem $WbioSrvc_ServiceProviders_RootKey 
Write-Host $WbioSrvc_ServiceProviders_RootKey 
ForEach ( $Key in  $Subkeys )
    {
    <#
        $Key | select *
        
        Name          : HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WbioSrvc\Service Providers\Voice
        PSIsContainer : True
        Property      : {BiometricType}
        PSChildName   : Voice
        ValueCount    : 1                 # only one Property
        SubKeyCount   : 2                 # two sub-folders
    #>
    $SubKey_Path = "$WbioSrvc_ServiceProviders_RootKey\$($Key.PSChildName)"
    $RegKey_Name = 'BiometricType'  
    $RegKey_Type = 'unknown'       #  SZ, DWORD, ..
    $RegKey_Value     = $NULL
    $RegKey_Value_HEX = $NULL
    $RegKey_ConsoleOutput = ""
    # Write-Host $SubKey_Path    # HKLM:SYSTEM\CurrentControlSet\Services\WbioSrvc\Service Providers\Voice

    if ((Get-Item -LiteralPath $SubKey_Path).GetValue($RegKey_Name, $null) -ne $null) 
        {
        $RegKey_Type = (Get-Item $SubKey_Path).GetValueKind($RegKey_Name) #  SZ, DWORD, ..
        # Write-Host  "'$RegKey_Name'  type  '$RegKey_Type'"  
     }
   
    $RegKey_Value = Get-ItemPropertyValue -path $SubKey_Path -name $RegKey_Name -ErrorAction SilentlyContinue
    if ( $RegKey_Type -eq 'DWord' ) 
        {
        $RegKey_Value_HEX = '0x{0:x}' -f $RegKey_Value    #  ->  0x80070013
        $RegKey_ConsoleOutput =  "( $RegKey_Value_HEX )"
        }
    Write-Host  "$($($Key.PSChildName).PadRight(15," "))   '$RegKey_Name'  type  '$RegKey_Type'  value '$($($RegKey_Value.ToString() + "'").PadRight(3," ")) $RegKey_ConsoleOutput "  
#region GlobalConfigurations
    # #################################
    $SubFolder = "Global Configurations"
    $SubKey_Path_GlobalConfigurations = "$SubKey_Path\$SubFolder"
    $RegKey2_Name  = 'ActiveConfiguration'   #  
    $RegKey2_Type  = $Null
    $RegKey2_Value = 'key does not exist'    #  None ( if never configured ), ...
    $RegKey2_Value_HEX = $Null
    $RegKey2_ConsoleOutput = ""
    
    # Write-Host "Regpath '$SubKey_Path_GlobalConfigurations'"
    [bool]$GlobalConfigurations_Exists = test-path $SubKey_Path_GlobalConfigurations
    if ( $GlobalConfigurations_Exists )
        {
        # ValueCount 
        # 
        # $SubKey_Path =                    "$WbioSrvc_ServiceProviders_RootKey\$($Key.PSChildName)"
        #                                   "HKLM:SYSTEM\CurrentControlSet\Services\WbioSrvc\Service Providers\Voice"
        # SubKey_Path_GlobalConfigurations  "$WbioSrvc_ServiceProviders_RootKey\$($Key.PSChildName)\Global Configurations"
        if ((Get-Item -LiteralPath $SubKey_Path_GlobalConfigurations).GetValue($RegKey2_Name, $null) -ne $null) 
            {
            $RegKey2_Type = (Get-Item $SubKey_Path_GlobalConfigurations).GetValueKind($RegKey2_Name) #  SZ, DWORD, ..
            # Write-Host  "'$RegKey2_Name'  type  '$RegKey2_Type'"  
            }
        $RegKey2_Value = Get-ItemPropertyValue -path $SubKey_Path_GlobalConfigurations -name $RegKey2_Name -ErrorAction SilentlyContinue
        if ( $RegKey2_Type -eq 'DWord' ) 
            {
            $RegKey2_Value_HEX = '0x{0:x}' -f $RegKey_Value    #  ->  0x80070013
            $RegKey2_ConsoleOutput =  "( $RegKey2_Value_HEX )"
            }
        Write-Host  "$($($Key.PSChildName).PadRight(15," "))   '$($($RegKey2_Name + "'").PadRight(22," "))  = '$($($RegKey2_Value.ToString() + "'").PadRight(3," ")) $RegKey2_ConsoleOutput" 
                
       # Write-Host  "$($($Key.PSChildName).PadRight(15," "))   '$RegKey2_Name'  type  '$RegKey2_Type'  value '$($($RegKey2_Value.ToString() + "'").PadRight(3," ")) $RegKey2_ConsoleOutput"  
        }
    else
        {

        }
#endregion GlobalConfigurations
    
 #region VirtualSensors
    # #################################
    $SubFolder = "Virtual Sensors"
    $SubKey_Path_VirtualSensors = "$SubKey_Path\$SubFolder"
    
    $RegKey3_Name  = 'DeviceDescription'   #  
    $RegKey3_Type  =  $Null                #  
    $RegKey3_Value = 'key does not exist'  #  Windows Hello Face Virtual Software Device
    
    $RegKey4_Name  = 'Manufacturer'        #  
    $RegKey4_Type  =  $Null                #  
    $RegKey4_Value = 'key does not exist'  #  Microsoft Corporation

    $RegKey5_Name  = 'ModelName'           #  
    $RegKey5_Type  =  $Null                #  
    $RegKey5_Value = 'key does not exist'  #  Windows Hello Face Virtual Sensor
    
    $RegKey6_Name  = 'Capabilities'        #  
    $RegKey6_Type  =  $Null                #  Reg_Dword
    $RegKey6_Value = 'key does not exist'  #  Windows Hello Face Virtual Sensor
    $RegKey6_Value_HEX     = $Null
    $RegKey6_ConsoleOutput = $Null

    
    Write-Host "Regpath '$SubKey_Path_VirtualSensors'"
    [bool]$VirtualSensors_Exists = test-path $SubKey_Path_VirtualSensors
    if ( $VirtualSensors_Exists )
        {
        $VirtualSensorsCount = (Get-Item $SubKey_Path_VirtualSensors).SubKeyCount
        # SubKeyCount   : 2                 # 2  sub-folders
        # ValueCount    : 10                # 10 RegKeys in this folder
        if ($VirtualSensorsCount -gt 0)
            {
            $VirtualSensorsGuids = ((Get-childItem -LiteralPath $SubKey_Path_VirtualSensors)  | select PSChildName).PSChildName
            $VirtualSensorsGuids_Joined = $VirtualSensorsGuids -join ","
            Write-Host "'$VirtualSensorsCount' '$SubFolder' assigned - $VirtualSensorsGuids_Joined "
            
            ForEach ( $Guid in $VirtualSensorsGuids )
                {
                $SubKey_Path_VirtualSensorsGuid = "$SubKey_Path_VirtualSensors\$Guid"
                Write-Host "Regpath  $SubKey_Path_VirtualSensorsGuid"
                # $SubKey_Path =                    "$WbioSrvc_ServiceProviders_RootKey\$($Key.PSChildName)"
                #                                   "HKLM:SYSTEM\CurrentControlSet\Services\WbioSrvc\Service Providers\Voice"
                # SubKey_Path_VirtualSensors        "$WbioSrvc_ServiceProviders_RootKey\$($Key.PSChildName)\VirtualSensors"
                # SubKey_Path_VirtualSensorsGuid1   "$WbioSrvc_ServiceProviders_RootKey\$($Key.PSChildName)\VirtualSensors\$Guid"
                $RegKey3_Value = Get-ItemPropertyValue -path $SubKey_Path_VirtualSensorsGuid -name $RegKey3_Name -ErrorAction SilentlyContinue
                $RegKey4_Value = Get-ItemPropertyValue -path $SubKey_Path_VirtualSensorsGuid -name $RegKey4_Name -ErrorAction SilentlyContinue
                $RegKey5_Value = Get-ItemPropertyValue -path $SubKey_Path_VirtualSensorsGuid -name $RegKey5_Name -ErrorAction SilentlyContinue
                $RegKey6_Value = Get-ItemPropertyValue -path $SubKey_Path_VirtualSensorsGuid -name $RegKey6_Name -ErrorAction SilentlyContinue
                
                $RegKey6_Type = (Get-Item $SubKey_Path_VirtualSensorsGuid).GetValueKind($RegKey6_Name) #  SZ, DWORD, ..
                if ( $RegKey6_Type -eq 'DWord' ) 
                    {
                    $RegKey6_Value_HEX = '0x{0:x}' -f $RegKey6_Value    #  ->  128
                    $RegKey6_ConsoleOutput =  "( $RegKey6_Value_HEX )"
                    }
                
                Write-Host  "$($($Key.PSChildName).PadRight(15," "))   '$($($RegKey3_Name + "'").PadRight(22," "))  = '$($($RegKey3_Value.ToString() + "'").PadRight(3," "))"  
                Write-Host  "$($($Key.PSChildName).PadRight(15," "))   '$($($RegKey4_Name + "'").PadRight(22," "))  = '$($($RegKey4_Value.ToString() + "'").PadRight(3," "))"  
                Write-Host  "$($($Key.PSChildName).PadRight(15," "))   '$($($RegKey5_Name + "'").PadRight(22," "))  = '$($($RegKey5_Value.ToString() + "'").PadRight(3," "))"  
                Write-Host  "$($($Key.PSChildName).PadRight(15," "))   '$($($RegKey6_Name + "'").PadRight(22," "))  = '$($($RegKey6_Value.ToString() + "'").PadRight(3," ")) $RegKey6_ConsoleOutput "  
                
                # #################################
                $SubFolderConfigurations                  = "Configurations"
                $SubKey_Path_VirtualSensorsConfigurations = "$SubKey_Path\$SubFolder\$Guid\$SubFolderConfigurations"
                # Write-Host "Regpath '$SubKey_Path_VirtualSensorsConfigurations'"
                [bool]$VirtualSensorsConfigurations_Exists = test-path $SubKey_Path_VirtualSensorsConfigurations
                if ( $VirtualSensorsConfigurations_Exists )
                    {
                     Write-Host "Regpath '$SubKey_Path_VirtualSensorsConfigurations'"
                    $RegKey7_Name  = 'DefaultConfiguration'  #  
                    $RegKey7_Type  =  $Null                  #  
                    $RegKey7_Value = 'key does not exist'    #  
                    $RegKey7_Value = Get-ItemPropertyValue -path $SubKey_Path_VirtualSensorsConfigurations -name $RegKey7_Name -ErrorAction SilentlyContinue
                    Write-Host  "$($($Key.PSChildName).PadRight(15," "))   '$($($RegKey7_Name + "'").PadRight(22," "))  = '$($($RegKey7_Value.ToString() + "'").PadRight(3," "))"  
                    if ( $RegKey7_Value -ne $Null )
                        {
                        # #################################
                        $SubFolderConfigurationsNumber                  = $RegKey7_Value
                        $SubKey_Path_VirtualSensorsConfigurationsNUmber = "$SubKey_Path\$SubFolder\$Guid\$SubFolderConfigurations\$RegKey7_Value"
                        # Write-Host "Regpath '$SubKey_Path_VirtualSensorsConfigurations'"
                        [bool]$VirtualSensorsConfigurationsNumber_Exists = test-path $SubKey_Path_VirtualSensorsConfigurationsNUmber
                        if ( $VirtualSensorsConfigurationsNumber_Exists )
                            {
                            Write-Host "Regpath '$SubKey_Path_VirtualSensorsConfigurationsNUmber'"
                            $RegKey8_Name  = 'DatabaseId'  #  
                            $RegKey8_Type  =  $Null                  #  
                            $RegKey8_Value = 'key does not exist'    #  
                            $RegKey8_Value = Get-ItemPropertyValue -path $SubKey_Path_VirtualSensorsConfigurationsNUmber -name $RegKey8_Name -ErrorAction SilentlyContinue
                            Write-Host  "$($($Key.PSChildName).PadRight(15," "))   '$($($RegKey8_Name + "'").PadRight(22," "))  = '$($($RegKey8_Value.ToString() + "'").PadRight(3," "))"  
                            
                            
                            $RegKey9_Name  = 'SensorMode'  #  
                            $RegKey9_Type  =  $Null                  #  
                            $RegKey9_Value = 'key does not exist'    #  
                            $RegKey9_Value = Get-ItemPropertyValue -path $SubKey_Path_VirtualSensorsConfigurationsNUmber -name $RegKey9_Name -ErrorAction SilentlyContinue
                            Write-Host  "$($($Key.PSChildName).PadRight(15," "))   '$($($RegKey9_Name + "'").PadRight(22," "))  = '$($($RegKey9_Value.ToString() + "'").PadRight(3," "))"  
                            
                            $RegKey10_Name  = 'SystemSensor'  #  
                            $RegKey10_Type  =  $Null                  #  
                            $RegKey10_Value = 'key does not exist'    #  
                            $RegKey10_Value = Get-ItemPropertyValue -path $SubKey_Path_VirtualSensorsConfigurationsNUmber -name $RegKey9_Name -ErrorAction SilentlyContinue
                            Write-Host  "$($($Key.PSChildName).PadRight(15," "))   '$($($RegKey10_Name + "'").PadRight(22," "))  = '$($($RegKey10_Value.ToString() + "'").PadRight(3," "))"  
                            
                            
                            }
                        else
                            {
                            Write-Host "Regpath missing '$SubKey_Path_VirtualSensorsConfigurationsNUmber'"
                            }
                        }
                   }
                else
                    {
                    Write-Host "Regpath missing '$SubKey_Path_VirtualSensorsConfigurations'"
                    }
                
                } # END  ForEach ( $Guid in $VirtualSensorsGuids )
            } 
        else
            {
             # "Virtual Sensors"
            Write-Host "no '$SubFolder' is assigned "
            }
        }
    else
        {
        Write-Host  "missing registry sub folder '$SubKey_Path_VirtualSensors'" 
        }
#endregion VirtualSensors

    Write-Host  
    }