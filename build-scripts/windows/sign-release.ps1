# Sign the Windows release binaries in ./dist with Azure Artifact Signing.
# Required env: AZURE_SIGNING_TENANT_ID, AZURE_SIGNING_CLIENT_ID,
# ACTIONS_ID_TOKEN_REQUEST_URL, ACTIONS_ID_TOKEN_REQUEST_TOKEN.
# Usage: sign-release.ps1 <artifact-name>
param(
    [Parameter(Mandatory = $true)]
    [string]$Artifact
)

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

if (-not $env:AZURE_SIGNING_TENANT_ID -or -not $env:AZURE_SIGNING_CLIENT_ID) {
    throw "Release builds require Vault secret code-signing/azure (tenant_id, client_id)."
}
if (-not $env:ACTIONS_ID_TOKEN_REQUEST_URL -or -not $env:ACTIONS_ID_TOKEN_REQUEST_TOKEN) {
    throw "ACTIONS_ID_TOKEN_REQUEST_URL/TOKEN not available; ensure permissions.id-token: write is set"
}

$files = @(
    "dist/chia-vault-recover-$Artifact.exe",
    "dist/chia-vault-recover-gui-$Artifact.exe"
)
foreach ($file in $files) {
    if (-not (Test-Path $file)) {
        throw "Missing binary to sign: $file"
    }
}

$env:Path = "C:\Program Files (x86)\Windows Kits\10\App Certification Kit;$env:Path"

$toolsDir = Join-Path $env:RUNNER_TEMP "artifact-signing-client"
New-Item -ItemType Directory -Path $toolsDir -Force | Out-Null
Push-Location $toolsDir
try {
    Invoke-WebRequest -Uri "https://dist.nuget.org/win-x86-commandline/latest/nuget.exe" -OutFile nuget.exe
    .\nuget.exe install Microsoft.ArtifactSigning.Client -x -OutputDirectory .
    $dlib = Get-ChildItem -Recurse -Filter "Azure.CodeSigning.Dlib.dll" |
        Where-Object { $_.FullName -match '[\\/]x64[\\/]' } |
        Select-Object -First 1
    if (-not $dlib) {
        throw "Azure.CodeSigning.Dlib.dll (x64) not found after installing Microsoft.ArtifactSigning.Client"
    }
    $metadataPath = Join-Path $toolsDir "metadata.json"
    @{
        Endpoint = "https://wus2.codesigning.azure.net/"
        CodeSigningAccountName = "ChiaNetworkInc"
        CertificateProfileName = "ChiaNetworkInc"
        CorrelationId = "github-actions-$env:GITHUB_RUN_ID"
    } | ConvertTo-Json | Set-Content -Path $metadataPath
} finally {
    Pop-Location
}

$tokenFile = Join-Path $env:RUNNER_TEMP "azure-federated-token"
try {
    $tokenUrl = "$($env:ACTIONS_ID_TOKEN_REQUEST_URL)&audience=api://AzureADTokenExchange"
    $headers = @{ Authorization = "Bearer $($env:ACTIONS_ID_TOKEN_REQUEST_TOKEN)" }
    $response = Invoke-RestMethod -Uri $tokenUrl -Headers $headers -Method GET
    if (-not $response.value) {
        throw "Failed to obtain GitHub OIDC token for Azure federated credential"
    }
    Set-Content -Path $tokenFile -Value $response.value -NoNewline
    $response = $null
    $env:AZURE_FEDERATED_TOKEN_FILE = $tokenFile
    $env:AZURE_TOKEN_CREDENTIALS = "prod"
    $env:AZURE_TENANT_ID = $env:AZURE_SIGNING_TENANT_ID
    $env:AZURE_CLIENT_ID = $env:AZURE_SIGNING_CLIENT_ID

    foreach ($file in $files) {
        Write-Output "Signing $file"
        & signtool.exe sign /fd SHA256 /tr "http://timestamp.acs.microsoft.com" /td SHA256 `
            /dlib $dlib.FullName `
            /dmdf $metadataPath `
            $file
        if ($LASTEXITCODE -ne 0) {
            throw "Azure Artifact Signing failed for $file with exit code $LASTEXITCODE"
        }
        Write-Output "Verify signature"
        & signtool.exe verify /pa $file
        if ($LASTEXITCODE -ne 0) {
            throw "Signature verification failed for $file"
        }
    }
} finally {
    $env:AZURE_FEDERATED_TOKEN_FILE = $null
    if (Test-Path $tokenFile) {
        Set-Content -Path $tokenFile -Value "" -NoNewline
        Remove-Item -Path $tokenFile -Force -ErrorAction SilentlyContinue
    }
}
