param(
  [string]$ApiBaseUrl = "http://127.0.0.1:8080/api/v1",
  [string]$HealthBaseUrl = "http://127.0.0.1:8080",
  [ValidateSet("disabled", "enabled", "ignore")][string]$MetricsMode = "disabled",
  [string]$MetricsToken = ""
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

function Invoke-CurlJson {
  param(
    [Parameter(Mandatory = $true)][string]$Method,
    [Parameter(Mandatory = $true)][string]$Url,
    [hashtable]$Body,
    [string[]]$Headers = @(),
    [string]$CookieJar = ""
  )

  $tempBodyFile = $null
  $args = @(
    "-sS",
    "-X", $Method,
    "-w", "`nHTTPSTATUS:%{http_code}",
    $Url
  )

  if ($CookieJar -ne "") {
    $args += @("-c", $CookieJar, "-b", $CookieJar)
  }

  foreach ($h in $Headers) {
    $args += @("-H", $h)
  }

  if ($null -ne $Body) {
    $json = $Body | ConvertTo-Json -Compress
    $tempBodyFile = [System.IO.Path]::GetTempFileName()
    [System.IO.File]::WriteAllText($tempBodyFile, $json, [System.Text.UTF8Encoding]::new($false))
    $args += @("-H", "Content-Type: application/json", "--data-binary", "@$tempBodyFile")
  }

  try {
    $rawLines = & curl.exe @args
    if ($LASTEXITCODE -ne 0) {
      throw "curl failed for $Method $Url (exit code: $LASTEXITCODE)"
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
    throw "Unable to parse curl response status for $Method $Url. Raw: $raw"
  }

  $respBody = $raw.Substring(0, $idx)
  $statusText = $raw.Substring($idx + $marker.Length).Trim()

  $statusCode = 0
  if (-not [int]::TryParse($statusText, [ref]$statusCode)) {
    throw "Invalid HTTP status '$statusText' for $Method $Url"
  }

  $jsonObj = $null
  $trimmed = $respBody.Trim()
  if ($trimmed.Length -gt 0) {
    try {
      $jsonObj = ConvertFrom-JsonCompat -Json $trimmed -Depth 20
    } catch {
      $jsonObj = $null
    }
  }

  return [pscustomobject]@{
    Method = $Method
    Url    = $Url
    Status = $statusCode
    Body   = $respBody
    Json   = $jsonObj
  }
}

function Assert-StatusIn {
  param(
    [Parameter(Mandatory = $true)]$Response,
    [Parameter(Mandatory = $true)][int[]]$ExpectedStatuses,
    [Parameter(Mandatory = $true)][string]$Label
  )

  if (-not ($ExpectedStatuses -contains $Response.Status)) {
    throw "$Label expected one of [$($ExpectedStatuses -join ', ')] but got $($Response.Status). Body: $($Response.Body)"
  }
}

function Assert-ApiSuccess {
  param(
    [Parameter(Mandatory = $true)]$Response,
    [Parameter(Mandatory = $true)][string]$Label
  )

  if ($null -eq $Response.Json) {
    throw "$Label expected JSON body but got: $($Response.Body)"
  }

  if (-not $Response.Json.success) {
    throw "$Label expected success=true but got: $($Response.Body)"
  }
}

$cookieJar = [System.IO.Path]::GetTempFileName()
try {
  Write-Host "Running production smoke checks"
  Write-Host "API base: $ApiBaseUrl"
  Write-Host "Health base: $HealthBaseUrl"
  Write-Host "Metrics mode: $MetricsMode"
  Write-Host ""

  Write-Host "[1/6] Liveness check"
  $live = Invoke-CurlJson -Method "GET" -Url "$HealthBaseUrl/health"
  Assert-StatusIn -Response $live -ExpectedStatuses @(200) -Label "liveness"
  if ($null -eq $live.Json -or $live.Json.status -ne "ok") {
    throw "liveness expected status=ok. Body: $($live.Body)"
  }
  Write-Host "    OK"

  Write-Host "[2/6] Readiness check"
  $ready = Invoke-CurlJson -Method "GET" -Url "$HealthBaseUrl/health/ready"
  Assert-StatusIn -Response $ready -ExpectedStatuses @(200) -Label "readiness"
  if ($null -eq $ready.Json -or $ready.Json.status -ne "ok") {
    throw "readiness expected status=ok. Body: $($ready.Body)"
  }
  Write-Host "    OK"

  Write-Host "[3/6] Metrics exposure check"
  $metricsHeaders = @()
  if ($MetricsMode -eq "enabled" -and -not [string]::IsNullOrWhiteSpace($MetricsToken)) {
    $metricsHeaders += "Authorization: Bearer $MetricsToken"
  }
  $metricsResp = Invoke-CurlJson -Method "GET" -Url "$HealthBaseUrl/metrics" -Headers $metricsHeaders
  if ($MetricsMode -eq "disabled") {
    Assert-StatusIn -Response $metricsResp -ExpectedStatuses @(404) -Label "metrics disabled"
  } elseif ($MetricsMode -eq "enabled") {
    if ([string]::IsNullOrWhiteSpace($MetricsToken)) {
      Assert-StatusIn -Response $metricsResp -ExpectedStatuses @(401) -Label "metrics auth"
    } else {
      Assert-StatusIn -Response $metricsResp -ExpectedStatuses @(200) -Label "metrics enabled"
    }
  } else {
    Assert-StatusIn -Response $metricsResp -ExpectedStatuses @(200, 401, 403, 404) -Label "metrics ignore"
  }
  Write-Host "    OK (HTTP $($metricsResp.Status))"

  Write-Host "[4/6] Guest auth bootstrap"
  $guest = Invoke-CurlJson -Method "POST" -Url "$ApiBaseUrl/auth/guest" -CookieJar $cookieJar
  Assert-StatusIn -Response $guest -ExpectedStatuses @(200) -Label "guest session"
  Assert-ApiSuccess -Response $guest -Label "guest session"

  $token = $guest.Json.data.token
  $csrfToken = $guest.Json.data.csrf_token
  if ([string]::IsNullOrWhiteSpace($token) -or [string]::IsNullOrWhiteSpace($csrfToken)) {
    throw "guest session did not return token/csrf_token. Body: $($guest.Body)"
  }
  Write-Host "    OK"

  Write-Host "[5/6] Authenticated identity check"
  $meHeaders = @("Authorization: Bearer $token")
  $me = Invoke-CurlJson -Method "GET" -Url "$ApiBaseUrl/auth/me" -Headers $meHeaders -CookieJar $cookieJar
  Assert-StatusIn -Response $me -ExpectedStatuses @(200) -Label "auth/me"
  Assert-ApiSuccess -Response $me -Label "auth/me"
  Write-Host "    OK"

  Write-Host "[6/6] CSRF enforcement check"
  $csrfMissing = Invoke-CurlJson -Method "POST" -Url "$ApiBaseUrl/shares/" -Headers @("Authorization: Bearer $token") -Body @{} -CookieJar $cookieJar
  Assert-StatusIn -Response $csrfMissing -ExpectedStatuses @(403) -Label "csrf missing"

  $csrfPresent = Invoke-CurlJson -Method "POST" -Url "$ApiBaseUrl/shares/" -Headers @("Authorization: Bearer $token", "X-CSRF-Token: $csrfToken") -Body @{} -CookieJar $cookieJar
  Assert-StatusIn -Response $csrfPresent -ExpectedStatuses @(400) -Label "csrf present + invalid payload"
  Write-Host "    OK"

  Write-Host ""
  Write-Host "Smoke checks passed."
} finally {
  if (Test-Path $cookieJar) {
    Remove-Item -Force $cookieJar
  }
}
