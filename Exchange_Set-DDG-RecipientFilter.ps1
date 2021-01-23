$DDL = "..."
$MemberRule = "..."

Set-DynamicDistributionGroup -Identity "$DDL" -RecipientFilter {(RecipientType -eq 'UserMailbox') -and ($MemberRule)}
