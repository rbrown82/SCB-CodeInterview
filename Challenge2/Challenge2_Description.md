<#
.SYNOPSIS
    Parse a blocklist.txt and split entries into categorized .txt files.

.DESCRIPTION
    Reads an input blocklist (one item per line; can include comments or URLs),
    attempts to classify each entry into one of:
      - Country Code TLDs (two-letter TLDs, e.g. *.ru, .cn)
      - Top Level Domains (gTLD-like entries, e.g. *.info, .solutions)
      - Domain-Subdomain patterns (example.com, *.example.com, account-office-protections.example.biz, @.example.com)
      - Email Addresses (user@domain.tld)
      - IPv4 Addresses (validated)
      - IPv6 Addresses (validated)
    Writes one file per category (UTF-8) with one entry per line. Also writes unmatched.txt
    for lines the script couldn't classify.

.NOTES
    - The script is conservative: it removes surrounding quotes, URL schemes (http/https),
      trailing slashes, and inline comments (text after " #") before classification.
    - Email detection happens before IP detection so "user@192.168.1.1" is treated as an email.
    - IP detection uses .NET IPAddress.TryParse for robust validation (supports IPv4 and IPv6).
    - TLD detection accepts lines like "*.info", ".info" or "info" (no other dots). Two-letter
      TLDs are classified as Country-Code TLDs.
    - Domain-Subdomain classification is a fallback for anything containing at least one dot
      that wasn't classified earlier (so "*.example.com" => domain-subdomain; "*.info" =>
      top-level domain).
    - Duplicate entries are de-duplicated while preserving first-seen order.

.EXAMPLE
    .\Split-Blocklist.ps1 -InputFile ".\blocklist.txt" -OutputDir ".\split-output"

#>

param(
    [Parameter(Mandatory=$false)]
    [string]$InputFile = ".\blocklist.txt",

    [Parameter(Mandatory=$false)]
    [string]$OutputDir = ".\split-output"
)

# --- Utility logging function ---
function Write-Log {
    param(
        [string]$Message,
        [ValidateSet("INFO","WARN","ERROR","DEBUG")]
        [string]$Level = "INFO"
    )
    $ts = (Get-Date).ToString("s")
    Write-Output "[$ts] [$Level] $Message"
}

# --- Validate input file exists ---
if (-not (Test-Path -Path $InputFile)) {
    Write-Log "Input file '$InputFile' not found." "ERROR"
    throw "Input file not found: $InputFile"
}

# --- Prepare output directory ---
if (-not (Test-Path -Path $OutputDir)) {
    New-Item -Path $OutputDir -ItemType Directory | Out-Null
}

# --- Prepare containers for categorized entries (preserve order, uniqueness) ---
# Using List + HashSet for fast duplication checks while preserving insertion order.
function New-OrderedSet {
    $obj = [PSCustomObject]@{
        List = New-Object 'System.Collections.Generic.List[string]'
        Set  = New-Object 'System.Collections.Generic.HashSet[string]'
    }
    return $obj
}
$ccTlds      = New-OrderedSet
$tlds        = New-OrderedSet
$domains     = New-OrderedSet
$emails      = New-OrderedSet
$ipv4s       = New-OrderedSet
$ipv6s       = New-OrderedSet
$unmatched   = New-OrderedSet

function Add-If-New {
    param($container, [string]$value)
    if (-not [string]::IsNullOrWhiteSpace($value)) {
        # normalize: trim whitespace
        $v = $value.Trim()
        if (-not $container.Set.Contains($v)) {
            $null = $container.Set.Add($v)
            $null = $container.List.Add($v)
        }
    }
}

# Email regex: reasonably strict but not insanely complex (covers common cases).
# Note: local-part allows many common characters per RFC. This is a pragmatic regex.
$emailRegex = '^[A-Za-z0-9!#$%&''*+/=?^_`{|}~\.-]+@[A-Za-z0-9\.-]+\.[A-Za-z]{2,63}$'

# Read and process file line-by-line
$lineNumber = 0
Get-Content -LiteralPath $InputFile -ErrorAction Stop | ForEach-Object {
    $lineNumber++
    $raw = $_

    # Trim whitespace
    $line = $raw.Trim()

    # Skip empty lines
    if ($line -eq '') { return }

    # Skip comment lines that start with # or ;
    if ($line -match '^\s*[#;]') { return }

    # Remove inline comments that start with space+#
    # (keeps '#' if it's part of other tokens; this is a heuristic)
    if ($line -match '\s+#') {
        $line = $line -replace '\s+#.*$',''
        $line = $line.Trim()
        if ($line -eq '') { return }
    }

    # Remove surrounding quotes if present
    if ($line.StartsWith('"') -and $line.EndsWith('"')) {
        $line = $line.Trim('"')
    } elseif ($line.StartsWith("'") -and $line.EndsWith("'")) {
        $line = $line.Trim("'")
    }

    # Remove URL scheme (http:// or https://) if present
    $line = $line -replace '^(?i)https?://',''

    # Remove trailing slash if present (common with URL-like entries)
    if ($line.EndsWith('/')) { $line = $line.TrimEnd('/') }

    # Remove surrounding square brackets (e.g., [::1] -> ::1)
    if ($line -match '^\[(.+)\]$') { $line = $matches[1] }

    # Final trim
    $line = $line.Trim()
    if ($line -eq '') { return }

    # --- Classification order:
    #  1) Email addresses
    #  2) IP addresses (IPv4 / IPv6) validated via .NET
    #  3) TLD-only patterns like '*.info' or '.ru' or 'info' (no other dots)
    #     -> TLD length == 2 => country-code TLDs
    #     -> TLD length >= 3 => top-level domains
    #  4) Domain/Subdomain patterns (anything with a dot not captured above)
    #  5) Unmatched

    # 1) Email check
    if ($line -match $emailRegex) {
        Add-If-New $emails $line
        return
    }

    # 2) IP address check (use TryParse for robust validation)
    $parsedIP = $null
    try {
        $isIp = [System.Net.IPAddress]::TryParse($line, [ref]$parsedIP)
    } catch {
        $isIp = $false
    }
    if ($isIp) {
        # IPv4 vs IPv6
        if ($parsedIP.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork) {
            Add-If-New $ipv4s $parsedIP.ToString()
        } else {
            Add-If-New $ipv6s $parsedIP.ToString()
        }
        return
    }

    # 3) TLD-only pattern detection
    # Remove a single leading '*.' or leading '.' if present, then check that there are NO dots left.
    $candidate = $line -replace '^\*\.', '' -replace '^\.', ''
    if (($candidate -ne '') -and ($candidate -notmatch '\.') -and ($candidate -match '^[A-Za-z0-9-]{2,63}$')) {
        # If original form included only optional leading wildcards/dots (no other characters),
        # and the remainder has no dots, treat as a TLD pattern.
        # We enforce that the original string contains nothing but optional '*.' or '.' + the label,
        # i.e., no embedded path, no additional dots.
        if ($line -match '^(?:\*\.)?\.?[A-Za-z0-9-]{2,63}$') {
            if ($candidate.Length -eq 2) {
                Add-If-New $ccTlds $line
            } else {
                Add-If-New $tlds $line
            }
            return
        }
    }

    # 4) Domain/Subdomain detection:
    # Any remaining string with at least one dot is treated as a domain/subdomain pattern.
    # This includes patterns like "example.com", "*.example.com", "account-office-protections.example.biz",
    # and even the unusual "@.example.com" (user requested this grouping).
    if ($line -match '\.') {
        Add-If-New $domains $line
        return
    }

    # 5) Unmatched lines (store for review)
    Add-If-New $unmatched $line
}

# --- Write out files (one entry per line, UTF8) ---
function Write-ListToFile {
    param(
        [Parameter(Mandatory=$true)] $container,
        [Parameter(Mandatory=$true)][string]$fileName
    )
    $filePath = Join-Path -Path $OutputDir -ChildPath $fileName
    # If no entries, write an empty file (or you can skip; this writes an empty file)
    if ($container.List.Count -eq 0) {
        Set-Content -LiteralPath $filePath -Value @() -Encoding UTF8
    } else {
        # Write each element preserving the insertion order
        # Use Set-Content to overwrite existing file
        Set-Content -LiteralPath $filePath -Value $container.List -Encoding UTF8
    }
    Write-Log "Wrote $($container.List.Count) lines to $filePath" "INFO"
}

Write-ListToFile $ccTlds     "country-code-tlds.txt"
Write-ListToFile $tlds       "top-level-domains.txt"
Write-ListToFile $domains    "domain-subdomain.txt"
Write-ListToFile $emails     "email-addresses.txt"
Write-ListToFile $ipv4s      "ipv4-addresses.txt"
Write-ListToFile $ipv6s      "ipv6-addresses.txt"
Write-ListToFile $unmatched  "unmatched.txt"

# --- Summary to console ---
Write-Log "Parsing complete." "INFO"
Write-Log ("Country-code TLDs: {0}" -f $ccTlds.List.Count) "INFO"
Write-Log ("Top-level domains: {0}" -f $tlds.List.Count) "INFO"
Write-Log ("Domain/Subdomain entries: {0}" -f $domains.List.Count) "INFO"
Write-Log ("Email addresses: {0}" -f $emails.List.Count) "INFO"
Write-Log ("IPv4 addresses: {0}" -f $ipv4s.List.Count) "INFO"
Write-Log ("IPv6 addresses: {0}" -f $ipv6s.List.Count) "INFO"
Write-Log ("Unmatched lines: {0} (see unmatched.txt)" -f $unmatched.List.Count) "INFO"

# Exit with success
return 0
