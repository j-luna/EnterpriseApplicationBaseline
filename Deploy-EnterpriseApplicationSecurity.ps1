#Requires -Version 7.0
# Script to deploy Enterprise Application Security baselines.
# Connect to Microsoft Graph

$Scopes = @("Application.ReadWrite.All", "DelegatedPermissionGrant.ReadWrite.All", "Policy.ReadWrite.Authorization")
Connect-MgGraph -Scopes $Scopes -ErrorAction Stop

# Setup Graph API URLs
$ServicePrincipalUri = "https://graph.microsoft.com/v1.0/servicePrincipals"
$OAuthUri = "https://graph.microsoft.com/v1.0/oauth2PermissionGrants"
$AuthorizationPolicyUri = "https://graph.microsoft.com/v1.0/policies/authorizationPolicy"


# Create 'Apple Internet Accounts' Enterprise Application
$AIAResponse = Invoke-MgGraphRequest -Method POST `
    -Uri $ServicePrincipalUri `
    -Body (Get-Content -Path "./EnterpriseApplications/AppleInternetAccounts.json" -Raw) `
    -ContentType "application/json"

# If 'Apple Internet Accounts' already exists, grab the existing service principal ID to add OAuth 2.0 permissions
If ($null -eq $AIAResponse) {
    $AIAResponse = Invoke-MgGraphRequest -Method GET -Uri $ServicePrincipalUri -ContentType "application/json" `
        | Where-Object { $_.AppDisplayName -eq "Apple Internet Accounts" }
}

# Add OAuth 2.0 Permissions necessary for the 'Apple Internet Accounts' service principal
$OAuth2PermissionsJsons = Get-ChildItem -Path "./OAuth2Permissions"

ForEach ($OAuth2PermissionsJson in $OAuth2PermissionsJsons) {
    $OAuth2Permissions = Get-Content -Path $OAuth2PermissionsJson -Raw | ConvertFrom-Json -Depth 10
    $OAuth2Permissions.clientId = $AIAResponse.Id
    $OAuth2Permissions = $OAuth2Permissions | ConvertTo-Json -Depth 10

    Invoke-MgGraphRequest -Method POST -Uri $OAuthUri -Body $OAuth2Permissions -ContentType "application/json"
}

# Update User Consent authorization policy
$AuthorizationPolicyResponse = Invoke-MgGraphRequest -Method PATCH `
    -Uri $AuthorizationPolicyUri `
    -Body (Get-Content -Path "./AuthorizationPolicy/AuthorizationPolicy.json" -Raw) `
    -ContentType "application/json"


Write-Output "Exiting..."
Disconnect-MgGraph