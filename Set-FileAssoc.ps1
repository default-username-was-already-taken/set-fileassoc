<#
    .SYNOPSIS

        Sets Windows file associations on a per-user basis, bypassing the built-in protection.

    .DESCRIPTION

        This script allows a user or an IT administrator to change user file associations in Windows 10.

        User file associations in newer versions of Windows are normally protected from an unauthorized change,
        and therefore can only be set interactively through Settings app, or using a XML file pushed through GPO.

        The XML method has several drawbacks:
            - IT administrator has to keep track of any new associations when a Windows Feature Update gets released;
            - if the computer is not in a domain, associations can only be set in a reference image, and as a result:
                - apps also have to be pre-built in your image;
                - once an user changes one of their file associations, it cannot be set back using the XML method.

        A SetUserFTA tool has been made in 2017 to combat this limitation:
        https://kolbi.cz/blog/2017/10/25/setuserfta-userchoice-hash-defeated-set-file-type-associations-per-user/

        However, this tool is also not a perfect solution:
            - it only changes associations for the user that launched the tool;
            - this is problematic if computers are managed by means of a remote configuration administration tool,
              like Ansible;
            - workarounds to run SetUserFTA in different user contexts exist, but they are also not ideal;
            - closed-source model.

        For my personal use case (domainless network of Ansible-managed Windows 10 nodes with a "bleeding-edge" update policy),
        a different approach was needed, therefore, this script was made.

    .PARAMETER Extension

        Specifies a file extension that an association will be set for.

        Example: .pdf

    .PARAMETER ProgID

        Specifies the ProgID - an application/extension identifier for a file extension.
        ProgIDs can be found:
            - in HKCU:\Software\Classes for software that was installed in an user context;
            - in HKLM:\Software\Classes for system-wide software;
            - in HKCR: for a combined list of software (only works for your own user context).

        Examples:
            SumatraPDF
            VLC.mp4

    .PARAMETER SkipProgIDValidation

        Do not check if a ProgID actually exists for each user.
        If this parameter is specified, ProgID will always be set, even if it does not correspond to anything.

    .PARAMETER CurrentUser

        Specify this to explicitly use the script in current user context (default behaviour).

    .PARAMETER AllUsers

        Specify this to use the script for all valid local users.
        This will also try to change associations for service accounts and such, but these accounts normally
        do not have any association preferences, if they never were logged in to interactively.

        This parameter requires administrative privileges.

    .PARAMETER Users

        An array (comma-delimited list) of usernames.
        If this is set, this script will change settings only if an user's name exists in the array.

        Examples:
            user
            admin, paul, mike, lina

    .INPUTS

        None.

    .OUTPUTS

        System.Int32.

        -1: if nothing was changed, or a fatal error occurred.
         0: if associations were changed for at least one user.

    .EXAMPLE

        C:\> .\Set-FileAssoc.ps1 -Extension .pdf -ProgID SumatraPDF -AllUsers

    .EXAMPLE

        C:\> .\Set-FileAssoc.ps1 -Extension .html -ProgID ChromeHTML -Users user1, user2

    .NOTES
        This script was tested on Windows 10 Home 1909 and 2004.

        This script was originally made for personal use (and still is), and, therefore:
            - its author provides no guarantee that the product works, and/or will work on future versions of Windows;
            - does not have a SLA or even a guarantee that the product will be maintained within its lifecycle;
            - no obligations are made regarding user support and troubleshooting.

        This script is a product of reverse-engineering Windows binaries.
        Therefore, if your organization has to strictly adhere to Microsoft EULA,
        it may be problematic, legal-wise, to use this script, because:
            - it circumvents the measures set in place by Microsoft to prevent tampering with
              file associations and user experience;
            - it uses features that were implemented by reverse-engineering binaries that
              are "legally protected" from being reverse-engineered.

        Hash algorithm re-implementation is written in C# to avoid pitfalls with PowerShell arithmetic and integer overflows.

    .LINK

        https://github.com/default-username-was-already-taken
#>


#Requires -Version 5

[CmdletBinding(DefaultParameterSetName="CurrentUser", SupportsShouldProcess)]

Param (
    [Parameter(Mandatory, Position=0, HelpMessage="File extension", ParameterSetName="CurrentUser")]
    [Parameter(Mandatory, Position=0, HelpMessage="File extension", ParameterSetName="AllUsers")]
    [Parameter(Mandatory, Position=0, HelpMessage="File extension", ParameterSetName="SpecificUsers")]
    [ValidatePattern("\..+")]
    [String]$Extension,

    [Parameter(Mandatory, Position=1, HelpMessage="Program ID", ParameterSetName="CurrentUser")]
    [Parameter(Mandatory, Position=1, HelpMessage="Program ID", ParameterSetName="AllUsers")]
    [Parameter(Mandatory, Position=1, HelpMessage="Program ID", ParameterSetName="SpecificUsers")]
    [ValidateNotNullOrEmpty()]
    [String]$ProgID,

    [Parameter(ParameterSetName="CurrentUser", HelpMessage="Do not check if ProgID exists in per-user HKCR")]
    [Parameter(ParameterSetName="AllUsers", HelpMessage="Do not check if ProgID exists in per-user HKCR")]
    [Parameter(ParameterSetName="SpecificUsers", HelpMessage="Do not check if ProgID exists in per-user HKCR")]
    [Switch]$SkipProgIDValidation,

    [Parameter(ParameterSetName="CurrentUser", HelpMessage="Perform operations only on current user")]
    [Switch]$CurrentUser,

    [Parameter(ParameterSetName="AllUsers", HelpMessage="Perform operations on all users")]
    [Switch]$AllUsers,

    [Parameter(ParameterSetName="SpecificUsers", HelpMessage="Perform operations on specific users")]
    [ValidateNotNullOrEmpty()]
    [String[]]$Users
)

Set-StrictMode -Version 3

$RegQueryInfoKeySig = @"
    [DllImport("advapi32.dll", CharSet = CharSet.Auto)]
    extern public static Int32 RegQueryInfoKey(
        Microsoft.Win32.SafeHandles.SafeRegistryHandle hKey,
        StringBuilder lpClass,
        [In, Out] ref UInt32 lpcbClass,
        UInt32 lpReserved,
        out UInt32 lpcSubKeys,
        out UInt32 lpcbMaxSubKeyLen,
        out UInt32 lpcbMaxClassLen,
        out UInt32 lpcValues,
        out UInt32 lpcbMaxValueNameLen,
        out UInt32 lpcbMaxValueLen,
        out UInt32 lpcbSecurityDescriptor,
        out System.Runtime.InteropServices.ComTypes.FILETIME lpftLastWriteTime
    );
"@

Add-Type -Language CSharp @"
using System;

namespace SetFileAssoc.PatentHash
{
    public static class HashFuncs
    {

        public static uint[] WordSwap(byte[] a, int sz, byte[] md5)
        {
            if (sz < 2 || (sz & 1) == 1) {
                throw new ArgumentException(String.Format("Invalid input size: {0}", sz), "sz");
            }

            unchecked {
                uint o1 = 0;
                uint o2 = 0;
                int ta = 0;
                int ts = sz;
                int ti = ((sz - 2) >> 1) + 1;

                uint c0 = (BitConverter.ToUInt32(md5, 0) | 1) + 0x69FB0000;
                uint c1 = (BitConverter.ToUInt32(md5, 4) | 1) + 0x13DB0000;

                for (uint i = (uint)ti; i > 0; i--) {
                    uint n = BitConverter.ToUInt32(a, ta) + o1;
                    ta += 8;
                    ts -= 2;

                    uint v1 = 0x79F8A395 * (n * c0 - 0x10FA9605 * (n >> 16)) + 0x689B6B9F * ((n * c0 - 0x10FA9605 * (n >> 16)) >> 16);
                    uint v2 = 0xEA970001 * v1 - 0x3C101569 * (v1 >> 16);
                    uint v3 = BitConverter.ToUInt32(a, ta - 4) + v2;
                    uint v4 = v3 * c1 - 0x3CE8EC25 * (v3 >> 16);
                    uint v5 = 0x59C3AF2D * v4 - 0x2232E0F1 * (v4 >> 16);


                    o1 = 0x1EC90001 * v5 + 0x35BD1EC9 * (v5 >> 16);
                    o2 += o1 + v2;
                }

                if (ts == 1) {
                    uint n = BitConverter.ToUInt32(a, ta) + o1;

                    uint v1 = n * c0 - 0x10FA9605 * (n >> 16);
                    uint v2 = 0xEA970001 * (0x79F8A395 * v1 + 0x689B6B9F * (v1 >> 16)) -
                              0x3C101569 * ((0x79F8A395 * v1 + 0x689B6B9F * (v1 >> 16)) >> 16);
                    uint v3 = v2 * c1 - 0x3CE8EC25 * (v2 >> 16);

                    o1 = 0x1EC90001 * (0x59C3AF2D * v3 - 0x2232E0F1 * (v3 >> 16)) +
                         0x35BD1EC9 * ((0x59C3AF2D * v3 - 0x2232E0F1 * (v3 >> 16)) >> 16);
                    o2 += o1 + v2;
                }

                uint[] ret = new uint[2];
                ret[0] = o1;
                ret[1] = o2;
                return ret;
            }
        }

        public static uint[] Reversible(byte[] a, int sz, byte[] md5)
        {
            if (sz < 2 || (sz & 1) == 1) {
                throw new ArgumentException(String.Format("Invalid input size: {0}", sz), "sz");
            }

            unchecked {
                uint o1 = 0;
                uint o2 = 0;
                int ta = 0;
                int ts = sz;
                int ti = ((sz - 2) >> 1) + 1;

                uint c0 = BitConverter.ToUInt32(md5, 0) | 1;
                uint c1 = BitConverter.ToUInt32(md5, 4) | 1;

                for (uint i = (uint)ti; i > 0; i--) {
                    uint n = (BitConverter.ToUInt32(a, ta) + o1) * c0;
                    n = 0xB1110000 * n - 0x30674EEF * (n >> 16);
                    ta += 8;
                    ts -= 2;

                    uint v1 = 0x5B9F0000 * n - 0x78F7A461 * (n >> 16);
                    uint v2 = 0x1D830000 * (0x12CEB96D * (v1 >> 16) - 0x46930000 * v1) +
                              0x257E1D83 * ((0x12CEB96D * (v1 >> 16) - 0x46930000 * v1) >> 16);
                    uint v3 = BitConverter.ToUInt32(a, ta - 4) + v2;

                    uint v4 = 0x16F50000 * c1 * v3 - 0x5D8BE90B * (c1 * v3 >> 16);
                    uint v5 = 0x2B890000 * (0x96FF0000 * v4 - 0x2C7C6901 * (v4 >> 16)) +
                              0x7C932B89 * ((0x96FF0000 * v4 - 0x2C7C6901 * (v4 >> 16)) >> 16);

                    o1 = 0x9F690000 * v5 - 0x405B6097 * (v5 >> 16);
                    o2 += o1 + v2;
                }

                if (ts == 1) {
                    uint n = BitConverter.ToUInt32(a, ta) + o1;

                    uint v1 = 0xB1110000 * c0 * n - 0x30674EEF * ((c0 * n) >> 16);
                    uint v2 = 0x5B9F0000 * v1 - 0x78F7A461 * (v1 >> 16);
                    uint v3 = 0x1D830000 * (0x12CEB96D * (v2 >> 16) - 0x46930000 * v2) +
                              0x257E1D83 * ((0x12CEB96D * (v2 >> 16) - 0x46930000 * v2) >> 16);
                    uint v4 = 0x16F50000 * c1 * v3 - 0x5D8BE90B * ((c1 * v3) >> 16);
                    uint v5 = 0x96FF0000 * v4 - 0x2C7C6901 * (v4 >> 16);

                    o1 = 0x9F690000 * (0x2B890000 * v5 + 0x7C932B89 * (v5 >> 16)) -
                         0x405B6097 * ((0x2B890000 * v5 + 0x7C932B89 * (v5 >> 16)) >> 16);
                    o2 += o1 + v2;
                }

                uint[] ret = new uint[2];
                ret[0] = o1;
                ret[1] = o2;
                return ret;
            }
        }

        public static long MakeLong(uint left, uint right) {
           return (long)left << 32 | (long)right;
        }
    }
}
"@

$RegQueryInfoKey = Add-Type -MemberDefinition $RegQueryInfoKeySig -Name ImportedFuncs -Namespace RegQueryInfoKey -Using System.Text -PassThru





function Get-ObjectCount($Objects) {
    if (!$Objects) {
        return 0
    } else {
        return ($Objects | Measure).Count
    }
}

function Get-HKURootForUser($User) {
    try {
        if ($User.CU) {
            return "HKCU:"
        } else {
            $Root = "registry::HKEY_USERS\$($User.SID)"
            if (!(Test-Path $Root)) {
                throw "Root HKU subkey does not exist or is unavaliable"
            } else {
                return $Root
            }
        }
    } catch {
        Write-Warning "Failed to retrieve HKU subkey for user `"$($User.Name)`": $_"
    }

    return $null
}

function Get-HKUKeyForUser($User) {
    try {
        $Key = "$($User.Root)\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\$Extension\UserChoice"
        if (!(Test-Path $Key)) {
            throw "UserChoice subkey does not exist or is unavaliable"
        } else {
            return $Key
        }
    } catch {
        Write-Warning "Failed to retrieve UserChoice subkey for user `"$($User.Name)`": $_"
    }

    return $null
}


function Get-KeyWriteTimeForUser($User) {
    try {
        if ($User.Key -is [Microsoft.Win32.RegistryKey]) {
            $Key = $User.Key
        } else {
            $Key = Get-Item -Path $User.Key -ErrorAction Stop
            if (!$Key -or ($Key -isnot [Microsoft.Win32.RegistryKey])) {
                throw "Expected RegistryKey, got $($Key.GetType())"
            }
        }

        if (!$Key.Handle) {
            throw "Key handle is missing or set to 0"
        }

        $SBLen = 16384
        $SB = New-Object System.Text.StringBuilder -ArgumentList $SBLen
        $LastWriteTime = New-Object System.Runtime.InteropServices.ComTypes.FILETIME

        switch ($RegQueryInfoKey::RegQueryInfoKey($Key.Handle, $SB, [ref]$SBLen, $null, [ref]$null, [ref]$null, [ref]$null,
            [ref]$null, [ref]$null, [ref]$null, [ref]$null, [ref]$LastWriteTime)) {
            0 {
                $FTHigh = [System.BitConverter]::ToUInt32([System.BitConverter]::GetBytes($LastWriteTime.dwHighDateTime), 0)
                $FTLow = [System.BitConverter]::ToUInt32([System.BitConverter]::GetBytes($LastWriteTime.dwLowDateTime), 0)
                $FT = [datetime]::FromFileTime(([Int64]$FTHigh -shl 32) -bor $FTLow)

                $FTTrunc = (New-Object DateTime $FT.Year, $FT.Month, $FT.Day, $FT.Hour, $FT.Minute, 0, $FT.Kind).ToFileTime()

                return [string]::Format("{0:x8}{1:x8}", $FTTrunc -shr 32, $FTTrunc -band [uint32]::MaxValue)
            }

            default {
                throw "RegQueryInfoKey returned error code $_"
            }
        }
    } catch {
        Write-Warning "Failed to retrieve write time for UserChoice subkey for user `"$($User.Name)`": $_"
    }

    return $null
}


function Get-InputStringForUser($User) {
    return ("{0}{1}{2}{3}{4}" -f $Extension, $User.SID, $ProgID, $User.WriteTime,
        "User Choice set via Windows User Experience {D18B6DD5-6124-4341-9318-804003BAFA0B}").ToLowerInvariant()
}



function Get-IsUserSelected($User) {
    if ($CurrentUser) {
        return $User.CU
    } elseif ($Users) {
        return ($User.Name -in $Users)
    } else {
        return $true
    }
}

function Enumerate-Users {
    try {
        $SIDs = Get-CimInstance -Filter "LocalAccount=TRUE" -Class "Win32_UserAccount" | ? {$_.SID -notmatch "^S-1-5-21-(\d{10}-){3}5[0-9]{2}$"}

        if ($SIDs -and (Get-ObjectCount $SIDs) -ge 1) {
            $NewSIDs = $SIDs | select Name, SID, @{n="CU"; e={$_.SID -eq (([System.Security.Principal.WindowsIdentity]::GetCurrent()).User.Value)}}
            $NewSIDs = $NewSIDs | ? {(Get-IsUserSelected $_) -eq $true}

            return $NewSIDs
        }
    } catch {
        Write-Warning "Failed to enumerate user list through CIM"
    }

    return @()
}

function Set-UserKeyInfo($User) {
    return $User |
        select *, @{n="Root"; e={Get-HKURootForUser $_}} | ? Root -ne $null |
        select *, @{n="Key"; e={Get-HKUKeyForUser $_}} | ? Key -ne $null
}

function Set-UserExtraInfo($User) {
    return $User |
        select *, @{n="WriteTime"; e={Get-KeyWriteTimeForUser $_}} | ? WriteTime -ne $null |
        select *, @{n="InputString"; e={Get-InputStringForUser $_}} | ? InputString -ne $null
}

function Get-IsProgIDAvaliable($User) {
    if ($SkipProgIDValidation) {
        return $true
    }

    return (Test-Path "$($User.Root)\Software\Classes\$ProgID" -ErrorAction SilentlyContinue) -or
           (Test-Path "HKLM:\Software\Classes\$ProgID" -ErrorAction SilentlyContinue)
}

function Clear-UserChoice($User) {
    if (!$User.Key) {
        throw "No registry key provided for Clear-UserChoice"
    }

    if ($PSCmdlet.ShouldProcess($User.Key, "Clear-ItemProperty")) {
        Clear-ItemProperty -Path $User.Key -Name "Hash"
    }
}

function Set-UserChoice($User, $Hash) {
    if (!$Hash) {
        throw "No hash provided for Set-UserChoice"
    }

    if ($PSCmdlet.ShouldProcess($User.Key, "Set-ItemProperty")) {
        Set-ItemProperty -Path $User.Key -Name "ProgId" -Value $ProgID -Type String
        Set-ItemProperty -Path $User.Key -Name "Hash" -Value $Hash -Type String
    }
}



function Convert-StringToUTF16LEArray($Str) {
    return [System.Collections.ArrayList]([System.Text.Encoding]::Unicode.GetBytes($Str))
}

function Get-ArrayMD5Hash($A) {
    return [System.Security.Cryptography.HashAlgorithm]::Create("MD5").ComputeHash($A)
}

function Get-PatentHash([byte[]]$A, [byte[]]$MD5) {
    $Size = $A.Count
    $ShiftedSize = ($Size -shr 2) - ($Size -shr 2 -band 1) * 1

    [uint32[]]$A1 = [SetFileAssoc.PatentHash.HashFuncs]::WordSwap($A, [int]$ShiftedSize, $MD5);
    [uint32[]]$A2 = [SetFileAssoc.PatentHash.HashFuncs]::Reversible($A, [int]$ShiftedSize, $MD5);

    $Ret = [SetFileAssoc.PatentHash.HashFuncs]::MakeLong($A1[1] -bxor $A2[1], $A1[0] -bxor $A2[0]);
    return $Ret
}







{
    [System.Int32]$ReturnCode = -1

    if (!$CurrentUser -and !$AllUsers -and !$Users) {
        $CurrentUser = $true
    }

    $EnumeratedUsers = Enumerate-Users
    foreach ($User in $EnumeratedUsers) {
        $User = Set-UserKeyInfo $User
        if (!$User) {
            continue
        }

        try {
            Clear-UserChoice $User
        } catch {
            Write-Warning "Clear-UserChoice failed, skipping user `"$($User.Name)`""
            continue
        }

        $User = Set-UserExtraInfo $User
        if (!$User) {
            continue
        }


        try {
            $A = Convert-StringToUTF16LEArray $User.InputString
            $A += (0,0)

            $MD5 = Get-ArrayMD5Hash $A
            $PatentHash = Get-PatentHash $A $MD5

            $Hash = [System.Convert]::ToBase64String([System.BitConverter]::GetBytes([Int64]$PatentHash))

            Write-Verbose "Hash for user `"$($User.Name)`": $Hash"
        } catch {
            Write-Warning "Failed to calculate hash for `"$($User.Name)`", skipping this user"
            continue
        }


        try {
            Set-UserChoice -User $User -Hash $Hash
        } catch {
            Write-Warning "Set-UserChoice failed for user `"$($User.Name)`""
        }

        Write-Host "File association set for user `"$($User.Name)`": $Extension => $ProgID (hash `"$Hash`")"
        $ReturnCode = 0 # return 0 if at least one assoc was set correctly
    }

    exit $ReturnCode
}.Invoke()
