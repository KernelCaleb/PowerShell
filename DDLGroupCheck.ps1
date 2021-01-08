$GroupCheck = Get-DynamicDistributionGroup "All Corporate"
Get-Recipient -RecipientPreviewFilter $GroupCheck.RecipientFilter | Select Name