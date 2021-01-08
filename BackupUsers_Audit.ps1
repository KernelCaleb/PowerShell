$file = Get-Content "C:\Users\csnethen\OneDrive - Professional Case Management\Documents\IT\PowerShell\Input\Update_BackupUsers_2020-12-01.csv"
#$AzureADGroup = "Backup_Users"

#$GroupID = $(Get-AzureADGroup -SearchString "$AzureADGroup").ObjectId

#echo $GroupID

ForEach($user in $file){

    echo $user
    #$userID = $(Get-AzureADUser -Filter "UserPrincipalName eq '$user'").ObjectId
    #echo $userID
    
    Add-DistributionGroupMember -Identity "Backup_Users" -Member $user
}