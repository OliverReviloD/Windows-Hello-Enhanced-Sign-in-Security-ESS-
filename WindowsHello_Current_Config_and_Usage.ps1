Set-StrictMode -Version Latest

#region SetupLog
    $LogDir = "C:\Dell"
    $LogDirSubFolderName = "WindowsHello"
    $LogFilePath = "$LogDir\$LogDirSubFolderName"
    $LogFileName = $env:computername + "_WHfB_current_user_settings.log"
    $LogFileFullPath = $LogFilePath + "\" + $LogFileName

    # check if folder exists or create
    If (-Not (Test-Path -Path $LogDir -PathType Container)) 
        {
        $NewFolder = New-Item -Path $LogDir -ItemType "directory" 
        } 
    If (-Not (Test-Path -Path $LogFilePath -PathType Container)) 
        {
        $NewFolder = New-Item -Path $LogDir -Name $LogDirSubFolderName -ItemType "directory"
        } 
#endregion SetupLog


Function Main 
    {
    cls
    # Detect which WHfB method has been configured

    $UserInfo = Get-UserInformationForScripting
 #   $UserInfo 

 #   $OSInfo = Get-ComputerInformationForScripting
 #   $OSInfo 
    

    # Check WHfB reg key 
    $LoggedOnUserSID                    =  $UserInfo.LoggedOnUserSID
    $LoggedOnUserUsedCredentialProvider =  $UserInfo.LoggedOnUserWHfBCredentialProvider
    # '{F8A0B131-5F68-486c-8040-7E8FC3C85BB6}' { $CredentialProviderType = 'MS-Account (unmanaged?) - with PWD'}      # WLIDCredentialProvider  
    # '{D6886603-9D2F-4EB2-B667-1971041FA96B}' { $CredentialProviderType = 'PIN'}  

    
    # LoggedOnUserWHfBCredentialProvider : PIN
    $PinKeyPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\{D6886603-9D2F-4EB2-B667-1971041FA96B}\$LoggedOnUserSID"
    $PinValueName = "LogonCredsAvailable"

    $BioKeyPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WinBio\AccountInfo\$LoggedOnUserSID"
    $BioValueName = "EnrolledFactors"
    
    $exitcode = 1
    $exitmessage = "Uncaught error"
    $exitcode = 0
    
    $UserInfo  | Add-Member -Name 'WHfB_Result'                  -MemberType Noteproperty -Value 'Unknown'            
    Try {
        Write-host "Check 1 - is WH4B configured at - '...\Authentication\Credential Providers\{PIN-GUID}\<UserSID>'"
        $UserInfo  | Add-Member -Name 'LogonCredsAvailable'                  -MemberType Noteproperty -Value 'Unknown'
        
        $PinSetup = Get-ItemProperty -Path $PinKeyPath -Name $PinValueName -ErrorAction Continue
        $UserInfo.LogonCredsAvailable = $PinSetup.LogonCredsAvailable
        
        Write-host "...Check 2 - is at least PIN configured - 'LogonCredsAvailable -eq 1'"
        if ([int]$PinSetup.LogonCredsAvailable -eq 1) 
            {
            Write-host "... Check 2 - 'LogonCredsAvailable -eq 1' = TRUE"
            Write-host "......Check 3 - are any biometrics configured at - '...\WinBio\AccountInfo\<UserSID>'"  
            if (Test-Path -Path $BioKeyPath) {
                Write-host ".........Check 3 - are any biometrics configured - 'EnrolledFactors'"  
                $BioMetrics = Get-ItemProperty -Path $BioKeyPath -Name $BioValueName -ErrorAction Continue
                Write-host ".........Check 3 - which biometrics are configured"  
                if ($BioMetrics) 
                    {
                    switch ($BioMetrics.EnrolledFactors) 
                        {
                        0xa     { $exitmessage = "Face and Fingerprint configured" }
                        0x2     { $exitmessage = "Face configured" }
                        0x8     { $exitmessage = "Fingerprint configured" }
                        default { $exitmessage = "Unknown Biometric configured" }
                        }
                    Write-host ".........Check 3 - $exitmessage"
                    $UserInfo.WHfB_Result = $exitmessage
                    }
                else 
                    {
                    
                    $exitmessage = "LogonCredsAvailable Value does not exist"
                    Write-Warning "... Check 2 - $exitmessage"
                    $UserInfo.WHfB_Result = $exitmessage
                    $exitcode = 1
                    }
                } # END  of (Test-Path -Path $BioKeyPath) 
            else 
                {
                Write-host "......Check 3 - no biometrics"
                # Only PIN is configured
                $exitmessage = "PIN configured"
                Write-host "......Check 3 - $exitmessage"
                $UserInfo.WHfB_Result = $exitmessage
                $exitcode = 0
                }
            } # END   LogonCredsAvailable -eq 1
        else 
            {
            Write-host "...Check 2 - PIN not configured"
            $exitmessage = "Windows Hello not configured"
            Write-Warning $exitmessage
            $UserInfo.WHfB_Result = $exitmessage
            $exitcode = 1
            }
        }
    catch 
        {
        #  $PinKeyPath does not exist
        if ($_ -contains "Cannot find path")
            {
            $exitmessage = "Windows Hello not configured"
            Write-Warning $exitmessage
            $UserInfo.WHfB_Result = $exitmessage
            $exitcode = 1
            }
        else 
            {
            $exitmessage = "Something went wrong:" + $_
            Write-Error $exitmessage
            $UserInfo.WHfB_Result = $exitmessage
            $exitcode = 1
            }
        }
    
    Write-host "...Check 5 - Convenience-PIN"       
     $User_used_Convenience_PIN = Get-Convenience_PIN_used # -MyDebug
    Write-host "...Check 5 - $($User_used_Convenience_PIN.ResultText) - Return = $($User_used_Convenience_PIN.ResultCode)"
   # $User_used_Convenience_PIN 
   
    $UserInfo | Add-Member -Name 'BiometricsResultText'  -MemberType Noteproperty -Value $($exitmessage)
    $UserInfo | Add-Member -Name 'BiometricsResultCode'  -MemberType Noteproperty -Value $exitcode

    $UserInfo | Add-Member -Name 'PIN_UserSID'            -MemberType Noteproperty -Value $User_used_Convenience_PIN.LoggedOnUserSID
    $UserInfo | Add-Member -Name 'PIN_ResultText'         -MemberType Noteproperty -Value $User_used_Convenience_PIN.ResultText
    $UserInfo | Add-Member -Name 'PIN_ResultCode'         -MemberType Noteproperty -Value $User_used_Convenience_PIN.ResultCode
    
    return $UserInfo 
    }

Function Get-Convenience_PIN_used  {
    param ( [Switch]$MyDebug = $False )
    <#
        https://getrubix.com/blog/looking-for-something-use-a-remediation-GXD0c
        "Windows Hello for Business" used with "Convenience PIN"
    #>
    $loggedOnUserSID = (New-Object System.Security.Principal.NTAccount($env:username)).Translate([System.Security.Principal.SecurityIdentifier]).value 
    # {D6886603-9D2F-4EB2-B667-1971041FA96B} ->  NGC Credential Provider
    $value = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\{D6886603-9D2F-4EB2-B667-1971041FA96B}\$loggedOnUserSID" -ErrorAction SilentlyContinue | 
    Select -ExpandProperty "LogonCredsAvailable"

    $Dsregcmd = New-Object PSObject 
    Dsregcmd /status | Where {$_ -match ' : '} | ForEach { $Item = $_.Trim() -split ' : '; $Prop = $Item[0]; if($Item.count -eq 2) {$Val = $Item[1]} else { $val = $Null} ; if ( $MyDebug -ne $false ) { Write-Host "$Prop --- $Val" }; `
         $Dsregcmd | Add-Member -MemberType NoteProperty -Name $($Prop -replace '[:\s]','') -Value $Val -EA SilentlyContinue }
       

    #
    # https://learn.microsoft.com/en-us/entra/identity/devices/troubleshoot-device-dsregcmd#user-state
    #
    # https://www.google.com  - query for   "dsregcmd /status" "NgcSet : YES"
    #
    # When "dsregcmd /status" shows "NgcSet : YES", it indicates that 
    # - Windows Hello for Business (Next Generation Credential - NGC) is successfully configured and provisioned for the user on that device. 
    # - This means the device is prepared for biometric or PIN-based authentication, often used in conjunction with Azure AD Join or Hybrid Join

    $User_used_Convenience_PIN = New-Object -TypeName PSObject
    $User_used_Convenience_PIN | Add-Member -Name 'LoggedOnUserSID'           -MemberType Noteproperty -Value $loggedOnUserSID

    
    $ResultText = $Null
    $ResultCode = 9000

    $DsregcmdNgcSet = $Dsregcmd.NgcSet
    if(($value -eq 1) -and ($DsregcmdNgcSet -eq "NO"))  { $ResultText = "Convenience PIN detected (On-Premise or only-local). WRONG"  ; $ResultCode =  10 } 
    elseif($DsregcmdNgcSet -eq "YES")                   { $ResultText = "Windows Hello for Business key detected. OKAY ( DsRegCmd-NgcSet, no Convenience PIN )"       ; $ResultCode =  0 } 
    else                                                { $ResultText = "NO Convenience PIN or WHfB Key detected. WHfB-PIN missing"   ; $ResultCode =  20 }

    $User_used_Convenience_PIN | Add-Member -Name 'ResultText'                -MemberType Noteproperty -Value $ResultText
    $User_used_Convenience_PIN | Add-Member -Name 'ResultCode'                -MemberType Noteproperty -Value $ResultCode
    Return $User_used_Convenience_PIN
    }

Function Get-UserInformationForScripting {
    <#
    # import it in your script
    Write-Host ((Split-Path $MyInvocation.InvocationName) + "\Function_Get-UserInformationForScripting.ps1")
    . ((Split-Path $MyInvocation.InvocationName) + "\Function_Get-UserInformationForScripting.ps1")
    
    # call it in your script

    $UserInfo = Get-UserInformationForScripting
    $UserInfo 
    
        Return is a PS-CustomObject

        ScanTime                           : 2026-03-09 11:32
        LoggedOnUserSID                    : S-1-12-1-2224429591-1275072761-3089858232-xxxxxxxxx
        LoggedOnUserName                   : EUROPE\Oliver_Dd
        LoggedOnUserAuthType               : CloudAP
        LoggedOnUserIsSystem               : False
        LoggedOnUserWHfBCredentialProvider : PIN

    #>

    
    $UserInformation = New-Object -TypeName PSObject
    $SanDate = (Get-Date -Format "yyyy-MM-dd HH:mm" )
    $UserInformation | Add-Member -Name 'ScanTime'           -MemberType Noteproperty -Value $SanDate

    $LoggedOnUser = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    
    $LoggedOnUserSID = $LoggedOnUser.User.Value
    $UserInformation | Add-Member -Name 'LoggedOnUserSID'           -MemberType Noteproperty -Value $LoggedOnUserSID

    $LoggedOnUserName = $LoggedOnUser.Name
    $UserInformation | Add-Member -Name 'LoggedOnUserName'           -MemberType Noteproperty -Value $LoggedOnUserName

    $LoggedOnUserAuthType = $LoggedOnUser.AuthenticationType  # CloudAP = Entra
    $UserInformation | Add-Member -Name 'LoggedOnUserAuthType'           -MemberType Noteproperty -Value $LoggedOnUserAuthType

    $LoggedOnUserIsSystem = $LoggedOnUser.IsSystem            # True / False
    $UserInformation | Add-Member -Name 'LoggedOnUserIsSystem'           -MemberType Noteproperty -Value $LoggedOnUserIsSystem


    $LastLoggedOnProviderPath = "HKLM:SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\SessionData"
    $RegKey_Value1 = (Get-Item -LiteralPath $LastLoggedOnProviderPath).GetValue('LastLoggedOnProvider', $null)
    if ( $RegKey_Value1 -eq $Null )
        {
        $LastLoggedOnProviderPath = "HKLM:SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\SessionData\1"
        $RegKey_Value1 = (Get-Item -LiteralPath $LastLoggedOnProviderPath).GetValue('LastLoggedOnProvider', $null)
        }
    Switch ( $RegKey_Value1 )
            {
            '{27FBDB57-B613-4AF2-9D7E-4FA7A66C21AD}' { $CredentialProviderType = 'TrustedSignal'}              # TrustedSignal Credential Provider     
            '{C5D7540A-CD51-453B-B22B-05305BA03F07}' { $CredentialProviderType = 'Web-SignIn,CloudExperience'} #  Microsoft Cloud Experience                - cxcredprov.dll
            '{60b78e88-ead8-445c-9cfd-0b87f74ea6cd}' { $CredentialProviderType = 'Password'}                   # PasswordProvider ->  credprovs.dll   # required for "Run as admin" and "UAC prompts"
            '{D6886603-9D2F-4EB2-B667-1971041FA96B}' { $CredentialProviderType = 'PIN'}                        # NGC Credential Provider
            '{BEC09223-B018-416D-A0AC-523971B639F5}' { $CredentialProviderType = 'Fingerprint'}                # WinBio Credential Provider
            '{8AF662BF-65A0-4D0A-A540-A338A999D36F}' { $CredentialProviderType = 'Facial Recognition'}         # FaceCredentialProvider
             '{F8A0B131-5F68-486c-8040-7E8FC3C85BB6}' { $CredentialProviderType = 'MS-Account (unmanaged?) - with PWD'}      # WLIDCredentialProvider  
            default                                  { $CredentialProviderType = "$RegKey_Value1 -> unknown, maybe IRIS  scan"; Write-Host "Get-UserInformationForScripting() - Cred-Provider ='$RegKey_Value1' -please send a screenshot to Oliver" -ForegroundColor Red}   
            }
   # Write-Host "$RegKey_Value2 - logged in via Credential Provider '$RegKey_Value1' = $CredentialProviderType "
    $UserInformation | Add-Member -Name 'LoggedOnUserWHfBCredentialProvider'           -MemberType Noteproperty -Value $CredentialProviderType
    
    return $UserInformation

    }

Function Get-ComputerInformationForScripting {
    <#
    # import it in your script
    Write-Host ((Split-Path $MyInvocation.InvocationName) + "\Function_Get-ComputerInformationForScripting.ps1")
    . ((Split-Path $MyInvocation.InvocationName) + "\Function_Get-ComputerInformationForScripting.ps1")

    $OSInfo = Get-ComputerInformationForScripting
    $OSInfo 
    
        Return is a PS-CustomObject

        ScanTime           : 2026-03-09 10:15
        LastBootUpTime     : 2026-03-09 07:40
        ComputerName       : W-88N6234
        Manufacturer       : Dell Inc.
        Model              : Precision 5690
        SystemSkuNumber    : 0CC8
        ProcessorArch      : x64
        IsVirtualMachine   : No
        ServiceTag         : 88N6234
        BiosVersion        : 1.18.0 (2025-10-27)
        OperatingSystem    : Windows 11 Enterprise 24H2
        Version            : 10.0.26100
        OperatingSystemSKU : 4
        OSLanguage         : 1033
    #>

    # -----------------------------------------------------------------------------------
    # Check whether it is ARM architecture
    $ProcessorArch = "Unknown"
    try {
        $arch = (Get-WmiObject Win32_Processor -ErrorAction Stop).Architecture
        # 0 = x86, 9 = x64, 5 = ARM, 12 = ARM64
        if ($arch -eq 5 -or $arch -eq 12) { $ProcessorArch = "ARM" }
        if ($arch -eq 9                 ) { $ProcessorArch = "x64" }
        if ($arch -eq 0                 ) { $ProcessorArch = "x86" }
        }
    catch 
        {
        Write-Warning "Unable to determine CPU architecture, proceeding with defaults (x64).`n"
        $ProcessorArch = "x64"
        }

    # -----------------------------------------------------------------------------------
    # LastBootTime
    try {
        $OsInfo = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
        if ($null -eq $OsInfo -or $null -eq $OsInfo.LastBootUpTime) 
            {
            Write-Host "Warning - 'Win32_OperatingSystem.LastBootUpTime' is not available"
            $LastBootUpTime = $null
           } 
        else 
            {
            $LastBootUpTime = (Get-CIMInstance Win32_OperatingSystem).LastBootUpTime.ToString("yyyy-MM-dd HH:mm")  
            # Write-Host "Last Boot Time: '$LastBootUpTime'"
            }
        } 
    catch 
        {
        Write-Host "Warning - 'Win32_OperatingSystem.LastBootUpTime' is not available: $_"
        $LastBootUpTime = $null
        }

    $InventoryInformation = New-Object -TypeName PSObject

    $SanDate = (Get-Date -Format "yyyy-MM-dd HH:mm" )

    $ObjComputer        = Get-WMIObject Win32_ComputerSystem  | select PSComputerName,Manufacturer, Model, SystemSkuNumber

    $InventoryInformation | Add-Member -Name 'ScanTime'           -MemberType Noteproperty -Value $SanDate
    $InventoryInformation | Add-Member -Name 'LastBootUpTime'           -MemberType Noteproperty -Value $LastBootUpTime
    
    $InventoryInformation | Add-Member -Name 'ComputerName'       -MemberType Noteproperty -Value $ObjComputer.PSComputerName
    $InventoryInformation | Add-Member -Name 'Manufacturer'       -MemberType Noteproperty -Value $ObjComputer.Manufacturer
    $InventoryInformation | Add-Member -Name 'Model'              -MemberType Noteproperty -Value $ObjComputer.Model
    $InventoryInformation | Add-Member -Name 'SystemSkuNumber'    -MemberType Noteproperty -Value $ObjComputer.SystemSkuNumber
    $InventoryInformation | Add-Member -Name 'ProcessorArch'      -MemberType Noteproperty -Value $ProcessorArch

    # Yes / No / Unknown
    $IsVirtualMachine  = if ($ObjComputer -and $ObjComputer.Model -match "Virtual|VMware|VirtualBox|Hyper-V|QEMU|Parallels") { "Yes" } else { "No" } 
    $InventoryInformation | Add-Member -Name 'IsVirtualMachine'    -MemberType Noteproperty -Value $IsVirtualMachine
    

    $ObjBios               = Get-WMIObject Win32_Bios            | select SmBiosBiosVersion, SerialNumber,ReleaseDate
    $BiosReleaseDateString = " (" + (Get-CIMInstance Win32_BIOS).ReleaseDate.ToString("yyyy-MM-dd")  + ")"

    $InventoryInformation | Add-Member -Name 'ServiceTag'         -MemberType Noteproperty -Value $ObjBios.SerialNumber
    $InventoryInformation | Add-Member -Name 'BiosVersion'        -MemberType Noteproperty -Value ( $ObjBios.SmBiosBiosVersion + $BiosReleaseDateString)
    
    $RegKey  = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion"
    $RegName = "DisplayVersion"   #   21H2
    $RegValue = Get-ItemProperty $RegKey | Select-Object $RegName 
   # $InventoryInformation | Add-Member -Name 'DisplayVersion'     -MemberType Noteproperty -Value ($RegValue).DisplayVersion

    

    $ObjOperatingSystem = Get-WMIObject Win32_OperatingSystem | select Caption,Version, OperatingSystemSKU, OSLanguage 
    $OSName = $($ObjOperatingSystem.Caption).Replace("Microsoft ","") + " " + ($RegValue).DisplayVersion
    $InventoryInformation | Add-Member -Name 'OperatingSystem'    -MemberType Noteproperty -Value $OSName
    $InventoryInformation | Add-Member -Name 'Version'            -MemberType Noteproperty -Value $ObjOperatingSystem.Version
    $InventoryInformation | Add-Member -Name 'OperatingSystemSKU' -MemberType Noteproperty -Value $ObjOperatingSystem.OperatingSystemSKU
    $InventoryInformation | Add-Member -Name 'OSLanguage'         -MemberType Noteproperty -Value $ObjOperatingSystem.OSLanguage

    #   Get-ComputerInformationForScripting

    return $InventoryInformation
}

Start-Transcript $LogFileFullPath -Append


$UserInfo = Main
#                        0, 1, 2, ...                    0, 10, 20, 30, ..
$exitcode = $UserInfo.BiometricsResultCode + $UserInfo.PIN_ResultCode

 
Stop-Transcript
if ($host.name -eq "Windows PowerShell ISE Host") 
    { 
    Write-host "Script is started from PowerShell-ISE" 
    $UserInfo
    return $exitcode
    }
else
    { 
    Write-host "Script is started from console" 
    Exit $exitcode
    }

