# SBOMHub API Test Script
$baseUrl = "http://localhost:8080"
$results = @()

function Test-Endpoint {
    param(
        [string]$Name,
        [string]$Method,
        [string]$Url,
        [string]$Body = "",
        [int]$ExpectedStatus = 0
    )
    
    try {
        $params = @{
            Uri = $Url
            Method = $Method
            ContentType = "application/json"
            UseBasicParsing = $true
        }
        
        if ($Body -ne "") {
            $params.Body = $Body
        }
        
        $response = Invoke-WebRequest @params -ErrorAction Stop
        $status = $response.StatusCode
        $result = "PASS"
    }
    catch {
        $status = $_.Exception.Response.StatusCode.Value__
        if ($status -eq $null) {
            $status = 0
            $result = "ERROR - Connection failed"
        }
        elseif ($ExpectedStatus -ne 0 -and $status -eq $ExpectedStatus) {
            $result = "PASS (Expected $ExpectedStatus)"
        }
        elseif ($status -eq 401) {
            $result = "PASS (Auth Required)"
        }
        else {
            $result = "FAIL"
        }
    }
    
    return [PSCustomObject]@{
        Name = $Name
        Method = $Method
        Status = $status
        Result = $result
    }
}

Write-Host "========================================" -ForegroundColor Cyan
Write-Host " SBOMHub API Endpoint Test" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Public Endpoints
Write-Host "=== Public Endpoints ===" -ForegroundColor Yellow
$results += Test-Endpoint -Name "Health Check" -Method "GET" -Url "$baseUrl/api/v1/health"

# Auth Required Endpoints (should return 401)
Write-Host "=== Auth Required Endpoints ===" -ForegroundColor Yellow
$results += Test-Endpoint -Name "Get Stats" -Method "GET" -Url "$baseUrl/api/v1/stats" -ExpectedStatus 401
$results += Test-Endpoint -Name "Get Me" -Method "GET" -Url "$baseUrl/api/v1/me" -ExpectedStatus 401
$results += Test-Endpoint -Name "Dashboard Summary" -Method "GET" -Url "$baseUrl/api/v1/dashboard/summary" -ExpectedStatus 401
$results += Test-Endpoint -Name "Search by CVE" -Method "GET" -Url "$baseUrl/api/v1/search/cve?q=CVE-2021-44228" -ExpectedStatus 401
$results += Test-Endpoint -Name "Search by Component" -Method "GET" -Url "$baseUrl/api/v1/search/component?q=log4j" -ExpectedStatus 401

# Project Endpoints
$results += Test-Endpoint -Name "List Projects" -Method "GET" -Url "$baseUrl/api/v1/projects" -ExpectedStatus 401
$results += Test-Endpoint -Name "Create Project" -Method "POST" -Url "$baseUrl/api/v1/projects" -Body '{"name":"test"}' -ExpectedStatus 401

# Subscription Endpoints
$results += Test-Endpoint -Name "Get Subscription" -Method "GET" -Url "$baseUrl/api/v1/subscription" -ExpectedStatus 401
$results += Test-Endpoint -Name "Get Plan Usage" -Method "GET" -Url "$baseUrl/api/v1/plan/usage" -ExpectedStatus 401

# Sync Endpoints
$results += Test-Endpoint -Name "Sync EPSS" -Method "POST" -Url "$baseUrl/api/v1/vulnerabilities/sync-epss" -ExpectedStatus 401

# License Endpoints
$results += Test-Endpoint -Name "Get Common Licenses" -Method "GET" -Url "$baseUrl/api/v1/licenses/common" -ExpectedStatus 401

# Public Link (random token should return 404)
$results += Test-Endpoint -Name "Public Link (Invalid Token)" -Method "GET" -Url "$baseUrl/api/v1/public/invalid-token" -ExpectedStatus 404

# MCP Endpoints (API Key Auth)
Write-Host "=== MCP Endpoints (API Key Auth) ===" -ForegroundColor Yellow
$results += Test-Endpoint -Name "MCP Projects" -Method "GET" -Url "$baseUrl/api/v1/mcp/projects" -ExpectedStatus 401
$results += Test-Endpoint -Name "MCP Dashboard" -Method "GET" -Url "$baseUrl/api/v1/mcp/dashboard/summary" -ExpectedStatus 401

# Webhook Endpoints (POST only)
Write-Host "=== Webhook Endpoints ===" -ForegroundColor Yellow
$results += Test-Endpoint -Name "Clerk Webhook (No Sig)" -Method "POST" -Url "$baseUrl/api/webhooks/clerk" -Body '{}' -ExpectedStatus 400
$results += Test-Endpoint -Name "LemonSqueezy Webhook (No Sig)" -Method "POST" -Url "$baseUrl/api/webhooks/lemonsqueezy" -Body '{}' -ExpectedStatus 400

# Print Results
Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host " Test Results Summary" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

$results | Format-Table -Property Name, Method, Status, Result -AutoSize

$passed = ($results | Where-Object { $_.Result -like "PASS*" }).Count
$failed = ($results | Where-Object { $_.Result -like "FAIL*" }).Count
$errors = ($results | Where-Object { $_.Result -like "ERROR*" }).Count
$total = $results.Count

Write-Host ""
Write-Host "Total: $total | Passed: $passed | Failed: $failed | Errors: $errors" -ForegroundColor $(if ($failed -eq 0 -and $errors -eq 0) { "Green" } else { "Red" })
