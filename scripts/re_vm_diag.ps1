# re_vm_diag.ps1 — diagnostic helper for the VM toolchain live tests
Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue |
    Where-Object { $_.LocalPort -gt 8000 -and $_.LocalPort -lt 9000 } |
    Format-Table -AutoSize
Write-Host "---"
Get-Process -ErrorAction SilentlyContinue |
    Where-Object { $_.ProcessName -like "*python*" -or $_.ProcessName -like "*uv*" } |
    Select-Object Id, ProcessName, StartTime |
    Format-Table -AutoSize
Write-Host "---"
schtasks /Query /TN idalib-mcp-launcher /V /FO LIST 2>&1 | Out-String | Write-Host
