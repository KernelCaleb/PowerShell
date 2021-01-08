﻿Set-DynamicDistributionGroup -Identity “ClinicalOperationsCM@procasemanagement.com” -RecipientFilter {((RecipientType -eq 'UserMailbox') -and ((Department -eq 'Case Management') -and (Title -eq 'Case Manager')))}
Set-DynamicDistributionGroup -Identity “ClinicalOperationsSCM@procasemanagement.com” -RecipientFilter {((RecipientType -eq 'UserMailbox') -and ((Department -eq 'Clinical Administration') -and (Title -eq 'Senior Case Manager')))}
Set-DynamicDistributionGroup -Identity “AllClinicalOperationsAdmin@procasemanagement.com” -RecipientFilter {((RecipientType -eq 'UserMailbox') -and (((Department -eq 'Clinical Administration') -and ((Title -ne 'Case Manager') -and (Title -ne 'Senior Case Management')) -or (Title -eq 'Physical Therapist Lead'))))}