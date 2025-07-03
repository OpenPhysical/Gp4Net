#!/usr/bin/env pwsh
# Script to run trace validation tests

Write-Host "Running Gp4Net Trace Validation Tests" -ForegroundColor Cyan
Write-Host "====================================" -ForegroundColor Cyan

# Navigate to test directory
$testDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Push-Location $testDir

try {
    # Run specific test categories
    Write-Host "`nRunning Factory Unlock Tests..." -ForegroundColor Yellow
    dotnet test --filter "FullyQualifiedName~FactoryUnlockTests" --logger "console;verbosity=detailed"
    
    Write-Host "`nRunning GET DATA Command Tests..." -ForegroundColor Yellow
    dotnet test --filter "FullyQualifiedName~GetDataCommandTests" --logger "console;verbosity=detailed"
    
    Write-Host "`nRunning SCP02 Session Tests..." -ForegroundColor Yellow
    dotnet test --filter "FullyQualifiedName~Scp02SessionTests" --logger "console;verbosity=detailed"
    
    Write-Host "`nRunning Trace Validation Tests..." -ForegroundColor Yellow
    dotnet test --filter "FullyQualifiedName~TraceValidationTests" --logger "console;verbosity=detailed"
    
    Write-Host "`nRunning Installation Workflow Tests..." -ForegroundColor Yellow
    dotnet test --filter "FullyQualifiedName~InstallationWorkflowTests" --logger "console;verbosity=detailed"
    
    Write-Host "`nAll trace validation tests completed!" -ForegroundColor Green
}
finally {
    Pop-Location
}