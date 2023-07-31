# https://learn.microsoft.com/en-us/dotnet/api/system.security.accesscontrol?view=net-7.0
using namespace System.Security.AccessControl;
# https://learn.microsoft.com/en-us/dotnet/api/system.security.principal?view=net-6.0
using namespace System.Security.Principal;


# https://learn.microsoft.com/en-us/dotnet/api/system.security.accesscontrol.filesystemaccessrule?view=net-6.0#constructors
# FileSystemAccessRule(IdentityReference, FileSystemRights, InheritanceFlags, PropagationFlags, AccessControlType)
# FileSystemRights - https://learn.microsoft.com/en-us/dotnet/api/system.security.accesscontrol.filesystemrights?view=net-6.0
function GetACEFullControl {
    param ([string]$object)

    return New-Object FileSystemAccessRule(
        $object, 
        [FileSystemRights]::FullControl, 
        ([InheritanceFlags]::ContainerInherit + [InheritanceFlags]::ObjectInherit), 
        [PropagationFlags]::None, 
        [AccessControlType]::Allow)
}

function GetACEReadAndExecute {
    param (
        [string]$object
    )

    return New-Object FileSystemAccessRule(
        $object, 
        [FileSystemRights]::ReadAndExecute, 
        ([InheritanceFlags]::ContainerInherit + [InheritanceFlags]::ObjectInherit), 
        [PropagationFlags]::None, 
        [AccessControlType]::Allow)
}

function GetACEReadExecuteAndWrite {
    param (
        [string]$object
    )

    return New-Object FileSystemAccessRule(
        $object, 
        ([FileSystemRights]::ReadAndExecute + [FileSystemRights]::Write), 
        ([InheritanceFlags]::ContainerInherit + [InheritanceFlags]::ObjectInherit), 
        [PropagationFlags]::None, 
        [AccessControlType]::Allow)
}

function GetACESimpleReadAndWrite {
    param (
        [string]$object
    )

    return New-Object FileSystemAccessRule(
        $object, 
        ([FileSystemRights]::ReadData + [FileSystemRights]::WriteData), 
        ([InheritanceFlags]::ContainerInherit + [InheritanceFlags]::ObjectInherit), 
        [PropagationFlags]::None, 
        [AccessControlType]::Allow)
}

function GetACERead {
    param (
        [string]$object
    )

    return New-Object FileSystemAccessRule(
        $object, 
        ([FileSystemRights]::Read), 
        ([InheritanceFlags]::ContainerInherit + [InheritanceFlags]::ObjectInherit), 
        [PropagationFlags]::None, 
        [AccessControlType]::Allow)
}

function GetACEUnknownSpecial {
    param (
        [string]$object
    )

    return New-Object FileSystemAccessRule(
        $object, 
        ([FileSystemRights]::AppendData + [FileSystemRights]::ReadData),
        ([InheritanceFlags]::ObjectInherit),
        [PropagationFlags]::None, 
        [AccessControlType]::Allow)
}


function GetACEFullControlContainer {
    param (
        [string]$object
    )

    return New-Object FileSystemAccessRule(
        $object, 
        [FileSystemRights]::FullControl, 
        [InheritanceFlags]::ContainerInherit, 
        [PropagationFlags]::None, 
        [AccessControlType]::Allow)
}

function GetACEReadExecuteAndWriteContainer {
    param (
        [string]$object
    )

    return New-Object FileSystemAccessRule(
        $object, 
        ([FileSystemRights]::ReadAndExecute + [FileSystemRights]::Write), 
        [InheritanceFlags]::ContainerInherit, 
        [PropagationFlags]::None, 
        [AccessControlType]::Allow)
}

function GetACEReadAndExecuteContainer {
    param (
        [string]$object
    )

    return New-Object FileSystemAccessRule(
        $object, 
        [FileSystemRights]::ReadAndExecute, 
        [InheritanceFlags]::ContainerInherit, 
        [PropagationFlags]::None, 
        [AccessControlType]::Allow)
}


function Get-ACLDefault {
    param ([string]$Path)

    $acl = Get-Acl -Path $Path
    # protect the access rules associated with this ObjectSecurity object from inheritance
    $acl.SetAccessRuleProtection($true, $false)

    # System, Administrators and file owner should have full access to created files
    $creatorSystemAce = GetACEFullControl -object "NT AUTHORITY\SYSTEM"
    $creatorAdministratorsAce = GetACEFullControl -object "BUILTIN\Administrators"
    $creatorOwnerAce = GetACEFullControl -object "CREATOR OWNER"

    $acl.AddAccessRule($creatorSystemAce)
    $acl.AddAccessRule($creatorAdministratorsAce)
    $acl.AddAccessRule($creatorOwnerAce)

    return $acl
}

function Set-ACLDefault{
    param ([string]$Path)
    $d_acl = Get-ACLDefault -Path $Path
    Set-Acl -Path $Path -AclObject $d_acl
}

function SetOwner {
    param (
        [string]$Path,
        [string]$Owner
    )

    $ownerIdentity = New-Object NTAccount($Owner)
    $acl = Get-ACLDefault -Path $Path

    $acl.SetOwner($ownerIdentity)

    Set-Acl -Path $Path -AclObject $acl
}

function CreateDirecory {
    param([string]$Path)
    New-Item -Path $Path -ItemType "Directory"
    Set-ACLDefault -Path $Path
}





$home_dir = "C:\home"
CreateDirecory -Path $home_dir

# There is a general directory where everyone has full permissions.
$share_dir = "C:\home\share"
CreateDirecory -Path $share_dir

# There is a special directory, which is accessible only to specified users. 
$spec_dir = "C:\home\spec"
CreateDirecory -Path $spec_dir
$special_members = @("Boss", "Alice", "Tom")


$users_and_groups = @(
    @("SysAdmins", "GodMode"),
    @("CEO", "Boss"),
    @("Administration", "Alice", "Gabi"),
    @("Managers", "Anthony", "Elisa", "Jolie", "Tom"),
    @("Unknown", "Supreme")
)

$super_users = @("Boss", "GodMode")
$super_groups = @("CEO", "SysAdmins")
$top_groups = @()

# Creates users and groups
# Assign users to the group they belong to
foreach ($element in $users_and_groups) {
    $group = $element[0]
    $users = $element[1..($element.length)]
    $group_obj = New-LocalGroup -Name $group
    $top_groups += $group

    # Every one has access to share directory
    $acl = Get-Acl -Path $share_dir
    $ace = GetACEFullControl -object $group
    $acl.AddAccessRule($ace)
    Set-Acl -Path $share_dir -AclObject $acl

    foreach ($u in $users) {
        #create user
        $usr_obj = New-LocalUser -Name $u -NoPassword

        # Add to Windows default Users group
        Add-LocalGroupMember -Group $(Get-LocalGroup -Name "Users") -Member $usr_obj
        # Add to group specific group
        Add-LocalGroupMember -Group $group_obj -Member $usr_obj

        # Change permissions to home directory
        $acl = Get-Acl -Path $home_dir
        if ($u -in $super_users){
            $ace = GetACEFullControl -object $u
        }
        else{
            $ace = GetACEReadAndExecuteContainer -object $u
        }
        $acl.AddAccessRule($ace)
        Set-Acl -Path $home_dir -AclObject $acl

        # Create user directory
        $user_dir = $home_dir+"\"+$u
        CreateDirecory -Path $user_dir
        SetOwner -Path $user_dir -Owner $u

        # Allow users from same group read
        $ace = GetACERead -object $group
        $acl = Get-Acl -Path $user_dir
        $acl.AddAccessRule($ace)
        Set-Acl -Path $user_dir -AclObject $acl

        # Allow users from top group read
        # But CEO and GodMod have full permissions 
        foreach ($top_gr in ($top_groups -ne $group) ){
            if ($top_gr -in $super_groups){
                $ace = GetACEFullControl -object $top_gr
            }
            else{
                $ace = GetACERead -object $top_gr
            }
            $acl = Get-Acl -Path $user_dir
            $acl.AddAccessRule($ace)
            Set-Acl -Path $user_dir -AclObject $acl
        }

        # Some users have access to special folder
        if ($u -in $special_members){
            $acl = Get-Acl -Path $spec_dir
            $ace = GetACEFullControl -object $u
            $acl.AddAccessRule($ace)
            Set-Acl -Path $spec_dir -AclObject $acl
        }
    }
}

# Select directory, which belongs to the CEO, and grant write permission to accountant (Alice)
$ceo_dir = $home_dir + "\" + "Boss"
$acl = Get-Acl -Path $ceo_dir
$ace = GetACESimpleReadAndWrite -object "Alice"
$acl.AddAccessRule($ace)
Set-Acl -Path $ceo_dir -AclObject $acl

# For the Unknown, choose a complex permission scheme of your choice. 
$unknown_dir = "C:\home\external_support"
CreateDirecory -Path $unknown_dir
SetOwner -Path $unknown_dir -Owner "Boss"
$ace1 = GetACEReadAndExecuteContainer -object "Unknown"
$ace2 = GetACEUnknownSpecial -object "Unknown"
$acl = Get-Acl -Path $unknown_dir
$acl.AddAccessRule($ace1)
$acl.AddAccessRule($ace2)
Set-Acl -Path $unknown_dir -AclObject $acl






# Set password policy according to current situation and modern requirements in IT world: password strength, minimum password length, maximum password age
# Activate event logging
$temp_cfg = $home_dir + "\GodMode\temp.cfg"
SecEdit.exe /export /cfg $temp_cfg
# String to replace for password policy and event audit
# https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/password-policy
# Audit - https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpsb/01f8e057-f6a8-4d6e-8a00-99bcd241b403
$cfg_strings = @(
    @("MinimumPasswordAge = 0", "MinimumPasswordAge = 15"),
    @("MaximumPasswordAge = 42", "MaximumPasswordAge = 60"),
    @("MinimumPasswordLength = 0", "MinimumPasswordLength = 10"),
    @("PasswordComplexity = 0", "PasswordComplexity = 1"),
    @("PasswordHistorySize = 0", "PasswordHistorySize = 24"),
    @("AuditSystemEvents = 0", "AuditSystemEvents = 3"),
    @("AuditLogonEvents = 0", "AuditLogonEvents = 3"),
    @("AuditObjectAccess = 0", "AuditObjectAccess = 3"),
    @("AuditPrivilegeUse = 0", "AuditPrivilegeUse = 3"),
    @("AuditPolicyChange = 0", "AuditPolicyChange = 3"),
    @("AuditAccountManage = 0", "AuditAccountManage = 3"),
    @("AuditAccountLogon = 0", "AuditAccountLogon = 3")
    )
foreach($element in $cfg_strings){
    $current_pol = $element[0]
    $chg_pol = $element[1]
    (Get-Content $temp_cfg).Replace($current_pol, $chg_pol) | Out-File $temp_cfg
}
SecEdit.exe /configure /db c:\windows\security\local.sdb /cfg $temp_cfg /areas SECURITYPOLICY


# Prohibit employees from
# customizing display settings,
# changing desktop wallpaper,
Set-ItemProperty -Path HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies -Name NoChangingWallPaper -Value 1 
#shutting down computer, 
#read removable drives.