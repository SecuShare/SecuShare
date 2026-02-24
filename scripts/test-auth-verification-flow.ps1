param(
  [string]$BaseUrl = "http://localhost:8080/api/v1",
  [string]$Email = "",
  [string]$Password = "Passw0rd!123",
  [switch]$SkipLegacyChecks
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function ConvertFrom-JsonCompat {
  param(
    [Parameter(Mandatory = $true)][string]$Json,
    [int]$Depth = 20
  )

  if ($PSVersionTable.PSVersion.Major -ge 6) {
    return ($Json | ConvertFrom-Json -Depth $Depth)
  }

  return ($Json | ConvertFrom-Json)
}

if ([string]::IsNullOrWhiteSpace($Email)) {
  $Email = "auth-test-$([DateTimeOffset]::UtcNow.ToUnixTimeSeconds())@example.com"
}

function Invoke-Api {
  param(
    [Parameter(Mandatory = $true)][string]$Method,
    [Parameter(Mandatory = $true)][string]$Path,
    [hashtable]$Body
  )

  $url = "$BaseUrl$Path"
  $tempBodyFile = $null
  $args = @(
    "-sS",
    "-X", $Method,
    "-H", "Content-Type: application/json",
    "-w", "`nHTTPSTATUS:%{http_code}",
    $url
  )

  if ($null -ne $Body) {
    $json = $Body | ConvertTo-Json -Compress
    $tempBodyFile = [System.IO.Path]::GetTempFileName()
    [System.IO.File]::WriteAllText($tempBodyFile, $json, [System.Text.UTF8Encoding]::new($false))
    $args += @("--data-binary", "@$tempBodyFile")
  }

  try {
    $rawLines = & curl.exe @args
    if ($LASTEXITCODE -ne 0) {
      throw "curl failed for $Method $Path (exit code: $LASTEXITCODE)"
    }
  } finally {
    if ($null -ne $tempBodyFile -and (Test-Path $tempBodyFile)) {
      Remove-Item -Force $tempBodyFile
    }
  }
  $raw = ($rawLines -join "`n")

  $marker = "`nHTTPSTATUS:"
  $idx = $raw.LastIndexOf($marker)
  if ($idx -lt 0) {
    throw "Unable to parse curl response status for $Method $Path. Raw response: $raw"
  }

  $respBody = $raw.Substring(0, $idx)
  $statusText = $raw.Substring($idx + $marker.Length).Trim()

  $statusCode = 0
  if (-not [int]::TryParse($statusText, [ref]$statusCode)) {
    throw "Invalid HTTP status in curl response for $Method ${Path}: '$statusText'"
  }

  $jsonObj = $null
  $apiSuccess = $null
  $message = $null
  $token = $null
  $trimmed = $respBody.Trim()
  if ($trimmed.Length -gt 0) {
    if ($trimmed -match '"success"\s*:\s*(true|false)') {
      $apiSuccess = ($matches[1] -eq "true")
    }
    if ($trimmed -match '"message"\s*:\s*"([^"]*)"') {
      $message = [System.Text.RegularExpressions.Regex]::Unescape($matches[1])
    }
    if ($trimmed -match '"token"\s*:\s*"([^"]*)"') {
      $token = $matches[1]
    }
    try {
      $jsonObj = ConvertFrom-JsonCompat -Json $trimmed -Depth 20
    } catch {
      $jsonObj = $null
    }
  }

  return [pscustomobject]@{
    Method = $Method
    Path   = $Path
    Status = $statusCode
    Body   = $respBody
    Json   = $jsonObj
    ApiSuccess = $apiSuccess
    Message = $message
    Token = $token
  }
}

function Assert-Status {
  param(
    [Parameter(Mandatory = $true)]$Response,
    [Parameter(Mandatory = $true)][int]$ExpectedStatus,
    [Parameter(Mandatory = $true)][string]$Label
  )

  if ($Response.Status -ne $ExpectedStatus) {
    throw "$Label expected HTTP $ExpectedStatus but got $($Response.Status). Body: $($Response.Body)"
  }
}

function Assert-ApiSuccessTrue {
  param(
    [Parameter(Mandatory = $true)]$Response,
    [Parameter(Mandatory = $true)][string]$Label
  )

  if ($null -eq $Response.ApiSuccess) {
    throw "$Label expected JSON response body with success flag. Raw body: $($Response.Body)"
  }

  if (-not $Response.ApiSuccess) {
    throw "$Label expected success=true. Body: $($Response.Body)"
  }
}

function Assert-ApiSuccessFalse {
  param(
    [Parameter(Mandatory = $true)]$Response,
    [Parameter(Mandatory = $true)][string]$Label
  )

  if ($null -eq $Response.ApiSuccess) {
    throw "$Label expected JSON response body with success flag. Raw body: $($Response.Body)"
  }

  if ($Response.ApiSuccess -ne $false) {
    throw "$Label expected success=false. Body: $($Response.Body)"
  }
}

Write-Host "Testing auth verification flow against: $BaseUrl"
Write-Host "Using email: $Email"

Write-Host ""
Write-Host "[1/6] Request registration verification code..."
$registerResp = Invoke-Api -Method "POST" -Path "/auth/register" -Body @{
  email    = $Email
  password = $Password
}
Assert-Status -Response $registerResp -ExpectedStatus 200 -Label "register"
Assert-ApiSuccessTrue -Response $registerResp -Label "register"
Write-Host "    register response: $($registerResp.Message)"

Write-Host ""
Write-Host "[2/6] Verify login fails before code verification..."
$loginBeforeResp = Invoke-Api -Method "POST" -Path "/auth/login" -Body @{
  email    = $Email
  password = $Password
}
Assert-Status -Response $loginBeforeResp -ExpectedStatus 401 -Label "login before verification"
Assert-ApiSuccessFalse -Response $loginBeforeResp -Label "login before verification"
Write-Host "    pre-verify login rejected as expected"

Write-Host ""
$code = Read-Host "[3/6] Enter the 6-digit verification code (from email or backend logs)"
if ($code -notmatch '^\d{6}$') {
  throw "Verification code must be exactly 6 digits."
}

Write-Host ""
Write-Host "[4/6] Verify registration code and create account..."
$verifyResp = Invoke-Api -Method "POST" -Path "/auth/register/verify" -Body @{
  email             = $Email
  verification_code = $code
}
Assert-Status -Response $verifyResp -ExpectedStatus 200 -Label "register verify"
Assert-ApiSuccessTrue -Response $verifyResp -Label "register verify"

$verifiedToken = $verifyResp.Token
if ([string]::IsNullOrWhiteSpace($verifiedToken)) {
  throw "register verify returned empty token. Body: $($verifyResp.Body)"
}
Write-Host "    account created, token received"

Write-Host ""
Write-Host "[5/6] Verify login succeeds after verification..."
$loginAfterResp = Invoke-Api -Method "POST" -Path "/auth/login" -Body @{
  email    = $Email
  password = $Password
}
Assert-Status -Response $loginAfterResp -ExpectedStatus 200 -Label "login after verification"
Assert-ApiSuccessTrue -Response $loginAfterResp -Label "login after verification"
$loginToken = $loginAfterResp.Token
if ([string]::IsNullOrWhiteSpace($loginToken)) {
  throw "login after verification returned empty token. Body: $($loginAfterResp.Body)"
}
Write-Host "    post-verify login succeeded"

if (-not $SkipLegacyChecks) {
  Write-Host ""
  Write-Host "[6/6] Check legacy registration endpoints are disabled..."

  $legacyInitResp = Invoke-Api -Method "POST" -Path "/auth/register/init" -Body @{
    email                = $Email
    registration_request = "dummy"
  }
  Assert-Status -Response $legacyInitResp -ExpectedStatus 410 -Label "legacy register init"
  Assert-ApiSuccessFalse -Response $legacyInitResp -Label "legacy register init"

  $legacyFinishResp = Invoke-Api -Method "POST" -Path "/auth/register/finish" -Body @{
    email               = $Email
    registration_record = "dummy"
  }
  Assert-Status -Response $legacyFinishResp -ExpectedStatus 410 -Label "legacy register finish"
  Assert-ApiSuccessFalse -Response $legacyFinishResp -Label "legacy register finish"

  Write-Host "    legacy endpoints return 410 as expected"
}

Write-Host ""
Write-Host "Flow validated successfully."
Write-Host "Email tested: $Email"
