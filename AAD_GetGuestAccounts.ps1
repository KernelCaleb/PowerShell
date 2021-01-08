# AAD Get-GuestAccounts

# KernelCaleb
# 2021-01-07

$path = "path to store the file"

Get-AzureADUser -Filter "Usertype eq 'Guest'” | Export-csv -path $path
