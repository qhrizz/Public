#Connect to AzureAD First!

$Roles = Get-MsolRole | ? Name -Like “*” 
foreach($Role in $Roles) 
{ 
    $RoleName = $Role.Name 
    $Members = Get-MsolRoleMember -RoleObjectId $Role.ObjectId 
    if($Members) 
    { 
        $Role.Name | Out-File -FilePath C:\temp\Admins.txt -Append -Encoding default -Force 
        $Members | Out-File -FilePath C:\temp\Admins.txt -Append -Encoding default -Force 
    } 
    else 
    { 
        $Role.Name | Out-File -FilePath C:\temp\Admins.txt -Append -Encoding default -Force 
        “No Members” | Out-File -FilePath C:\temp\Admins.txt -Append -Encoding default -Force 
    }  
}  
# You can also create a better CSV  
$UserRoles = @() 
$Roles = Get-MsolRole | ? Name -Like “*” 
foreach($Role in $Roles) 
{ 
    $RoleName = $Role.Name 
    $Members = Get-MsolRoleMember -RoleObjectId $Role.ObjectId 
    if($Members) 
    { 
        foreach($Member in $Members) 
        { 
            $Role = New-Object PSObject 
            Add-Member -input $Role noteproperty ‘RoleName’ $RoleName 
            Add-Member -input $Role noteproperty ‘RoleMemberType’ $Member.RoleMemberType 
            Add-Member -input $Role noteproperty ‘EmailAddress’ $Member.EmailAddress 
            Add-Member -input $Role noteproperty ‘DisplayName’ $Member.DisplayName 
            Add-Member -input $Role noteproperty ‘isLicensed’ $Member.isLicensed 
            $UserRoles += $Role 
        } 
    } 
    else 
    { 
        $Role = New-Object PSObject 
        Add-Member -input $Role noteproperty ‘RoleName’ $RoleName 
        Add-Member -input $Role noteproperty ‘RoleMemberType’ “” 
        Add-Member -input $Role noteproperty ‘EmailAddress’ “” 
        Add-Member -input $Role noteproperty ‘DisplayName’ “” 
        Add-Member -input $Role noteproperty ‘isLicensed’ “” 
        $UserRoles += $Role 
    } 
} 
$UserRoles | Out-GridView