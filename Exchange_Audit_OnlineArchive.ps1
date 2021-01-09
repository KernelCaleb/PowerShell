# Exchange Audit Online Archive

$path = "..."

Get-Mailbox -Filter {ArchiveStatus -Eq "None" -AND RecipientTypeDetails -eq "UserMailbox"} | Select UserPrincipalName | Export-CSV $path
