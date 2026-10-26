$ErrorActionPreference = "Stop"

$cloudflared = Get-Command cloudflared -ErrorAction SilentlyContinue
if (-not $cloudflared) {
    throw "cloudflared is not installed. Install it with: winget install --id Cloudflare.cloudflared"
}

$certificate = Join-Path $env:USERPROFILE ".commonroom\lan-root-ca.crt"
if (-not (Test-Path $certificate)) {
    throw "The API certificate was not found. Start the 'Run encrypted chat API' task first."
}

if (-not (Test-NetConnection -ComputerName 127.0.0.1 -Port 5000 -InformationLevel Quiet)) {
    throw "The API is not listening on port 5000. Start the 'Run encrypted chat API' task first."
}

$allowedEmail = Read-Host "Email address allowed to open the temporary link"
try {
    $parsedEmail = [System.Net.Mail.MailAddress]::new($allowedEmail)
} catch {
    throw "Enter a valid email address."
}
if ($parsedEmail.Address -ne $allowedEmail) {
    throw "Enter a valid email address."
}

Write-Host "Only $allowedEmail will pass Cloudflare email verification."
Write-Host "Keep this terminal open. Stop the temporary link with Ctrl+C."
& $cloudflared.Source tunnel --url "https://127.0.0.1:5000" --origin-ca-pool $certificate --allowed-mail $allowedEmail
if ($LASTEXITCODE -ne 0) {
    throw "cloudflared exited with code $LASTEXITCODE."
}
