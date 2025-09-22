<#
.SYNOPSIS
    Retrieve data from the Federal Reserve FRED API and save as JSON.

.DESCRIPTION
    Demonstrates calling a REST API with authentication (API key),
    saving the response as JSON, and handling suboptimal scenarios:
      - Network unavailable
      - API unavailable (5xx, timeout, etc.)
      - Rate limiting (HTTP 429)
      - Unexpected errors
    Also includes simple rate-limit monitoring to avoid overusing the API.

.NOTES
    - Requires a FRED API key. You can obtain one free at:
      https://fred.stlouisfed.org/docs/api/api_key.html
    - Replace YOUR_API_KEY_HERE with your key or pass it as a parameter.

.EXAMPLE
    .\Get-FredSeries.ps1 -ApiKey "abc123" -SeriesId "GNPCA"
#>

param (
    [Parameter(Mandatory = $true)]
    [string]$ApiKey,

    [Parameter(Mandatory = $true)]
    [string]$SeriesId, # e.g., "GNPCA" for Gross National Product

    [Parameter(Mandatory = $false)]
    [string]$OutputFile = ".\fred-series.json",

    [Parameter(Mandatory = $false)]
    [int]$MinRequestIntervalSeconds = 5
)

# --- Simple rate limiting: remember last call ---
$script:LastApiCall = $null

function Wait-For-RateLimit {
    if ($script:LastApiCall) {
        $elapsed = (New-TimeSpan -Start $script:LastApiCall -End (Get-Date)).TotalSeconds
        if ($elapsed -lt $MinRequestIntervalSeconds) {
            $wait = [math]::Ceiling($MinRequestIntervalSeconds - $elapsed)
            Write-Output "Rate limiting: waiting $wait seconds before next call..."
            Start-Sleep -Seconds $wait
        }
    }
    $script:LastApiCall = Get-Date
}

function Get-FredSeriesData {
    param (
        [string]$ApiKey,
        [string]$SeriesId
    )

    # Construct URL
    $url = "https://api.stlouisfed.org/fred/series/observations?series_id=$SeriesId&api_key=$ApiKey&file_type=json"

    Wait-For-RateLimit

    try {
        # Perform request with a timeout
        $response = Invoke-RestMethod -Uri $url -Method GET -TimeoutSec 15 -ErrorAction Stop

        return $response
    }
    catch [System.Net.WebException] {
        Write-Error "Network or connectivity issue: $($_.Exception.Message)"
        return $null
    }
    catch [System.Net.Http.HttpRequestException] {
        Write-Error "HTTP request failed: $($_.Exception.Message)"
        return $null
    }
    catch {
        Write-Error "Unexpected error: $($_.Exception.Message)"
        return $null
    }
}

function Save-Json {
    param (
        $Data,
        [string]$Path
    )

    try {
        $json = $Data | ConvertTo-Json -Depth 5
        Set-Content -Path $Path -Value $json -Encoding UTF8
        Write-Output "Data successfully saved to $Path"
    }
    catch {
        Write-Error "Failed to save JSON file: $($_.Exception.Message)"
    }
}

# --- Main ---
Write-Output "Requesting FRED series '$SeriesId'..."
$data = Get-FredSeriesData -ApiKey $ApiKey -SeriesId $SeriesId

if (-not $data) {
    Write-Error "No data retrieved. Exiting."
    exit 1
}

# Handle possible rate limiting / API-level error messages
if ($data.error_code -eq 429 -or $data.error_code -eq "rate_limit") {
    Write-Error "API rate limit exceeded. Try again later."
    exit 2
}

if ($data.error_message) {
    Write-Error "API returned error: $($data.error_message)"
    exit 3
}

# Save to JSON
Save-Json -Data $data -Path $OutputFile
