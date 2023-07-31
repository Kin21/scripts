



function CreateDirectory {
    param([string]$Path)
    New-Item -Path $Path -ItemType "Directory"
}




$home_dir = "C:\home"
CreateDirecory -Path $home_dir




$users_and_groups = @(
    @("SysAdmins", "GodMode"),
    @("CEO", "Boss"),
    @("Administration", "Alice", "Gabi"),
    @("Managers", "Anthony", "Elisa", "Jolie", "Tom"),
    @("Unknown", "Supreme")
)

$super_users = @("Boss", "GodMode")
$top_groups = @()

# Creates users and groups
# Assign users to the group they belong to
foreach ($element in $users_and_groups) {
    $group = $element[0]
    $users = $element[1..($element.length)]
    $group_obj = New-LocalGroup -Name $group
    foreach ($u in $users) {
        #create user
        $usr_obj = New-LocalUser -Name $u -NoPassword

        # Add to Windows default Users group
        Add-LocalGroupMember -Group $(Get-LocalGroup -Name "Users") -Member $usr_obj
        # Add to group specific group
        Add-LocalGroupMember -Group $group_obj -Member $usr_obj

        # Change permissions to home directory
        if ($u -in $super_users){
            $acl = GetACEFullControl -object $u
        }
        else{
            $acl = GetACEReadAndExecuteContainer -object $u
        }
        Set-Acl -Path $home_dir -AclObject $acl

        # Create user directory
        $user_dir = $home_dir+"\"+$u
        CreateDirecory -Path $user_dir
        $acl = GetACEFullControl -object $u
        Set-ACLDefault -Path $user_dir -AclObject $acl

        # Allow users from same group read
        $users_in_same_group = $element[1..($element.length)] - $u
        foreach ($other_u in $users_in_same_group){
            $acl = GetACEReadAndExecute -object $other_u
            Set-Acl -Path $user_dir -AclObject $acl
        }
        
    }
}