Get-AzureADSubscribedSku | Select SkuPartNumber
$licenses = Get-AzureADSubscribedSku
$licenses[3].ServicePlans

STANDARDPACK.ServicePlans