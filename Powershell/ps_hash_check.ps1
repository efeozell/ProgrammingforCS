$BotToken = "MUST_BE_FILLED"
$ChatID = "MUST_BE_FILLED"
$Url = "https://api.telegram.org/bot$BotToken/sendMessage"

$VTApiKey = "MUST_BE_FILLED"

Write-Host "=====================================" -ForegroundColor Cyan
Write-Host "Process Hash Check Starting: $(Get-Date)" -ForegroundColor Cyan
Write-Host "=====================================" -ForegroundColor Cyan

$processes = Get-Process
Write-Host "Total $($processes.Count) process found"

function Send-TelegramAlert($message) {
    $body = @{
        chat_id = $ChatID
        text = $message
        parse_mode = "Markdown"
    }

    try {
        $response = Invoke-RestMethod -Uri $Url -Method Post -Body $body -ErrorAction Stop
        if ($response.ok) {
            Write-Host " -> Telegram message was sent." -ForegroundColor Green
        }
    } catch {
        Write-Host " -> Telegram message wasnt sen: $($_.Exception.Message)" -ForegroundColor Yellow
    }
}

$results = foreach ($process in $processes) {

    try {
        $filePath = $process.MainModule.FileName
    } catch {
        continue
    }
    

    if ($filePath) {

        try {
            $hash = Get-FileHash -Path $filePath -Algorithm SHA256 -ErrorAction Stop
        } catch {
            Write-Host "[SKIPPED] $($process.Name) -> hash not taken: $($_.Exception.Message)" -ForegroundColor DarkGray
        }


        [PSCustomObject]@{
                'Process Name' = $process.Name
                'File Path' = $filePath
                'SHA256 Hash' = $hash.Hash
        }
    }
}

$uniqueResults =  $results | Group-Object -Property 'SHA256 Hash' | ForEach-Object {
    $_.Group | Select-Object -First 1
}

Write-Host "`n$($uniqueResults.Count) unique hash checking on the VirusTotal"

if ([string]::IsNullOrWhiteSpace($VTApiKey)) {
    Write-Host "[ERROR] VTApiKey variable must be defined" -ForegroundColor Red
    return
}

foreach ($result in $uniqueResults) {
    $hash = $result.'SHA256 Hash'

    $headers = @{
        "x-apikey" = $VTApiKey
    }
    #VT Hash control
    try {
        $vtResponse = Invoke-RestMethod -Method 'Get' -Uri "https://www.virustotal.com/api/v3/files/$hash" -Headers $headers -ErrorAction Stop
    } catch {
        Write-Host "  -> VT Query is failed: $($_.Exception.Message)" -ForegroundColor Yellow
        Start-Sleep -Seconds 15 #Rate limit protection
        continue
    }


    

    if ($vtResponse.data.attributes.last_analysis_stats.malicious -gt 0) {

        Write-Host "  -> RESULT: $malicious engine says malicious" -ForegroundColor Red

        $msg = "🚨 *Malicious Process Found*`n" +
           "Process Name: $($result.'Process Name')`n" +
           "Executable Path: $($result.'File Path')`n" +
           "SHA256 Hash: $hash`n" +
           "Detections: $malicious engines`n" +
           "Link: https://www.virustotal.com/gui/file/$hash"

        Send-TelegramAlert $msg
    } else {
        Write-Host "   -> RESULT: Clear" -ForegroundColor DarkGray
    }

    Start-Sleep -Seconds 15 #Rate limit protection
}

Write-Host "`n=====================================" -ForegroundColor Cyan
Write-Host "SUMMARY"
Write-Host "Scanned process   : $($processes.Count)"
Write-Host "Unique hash sum: $($uniqueResults.Count)"
Write-Host "Completed: $(Get-Date)" -ForegroundColor Cyan
Write-Host "=====================================" -ForegroundColor Cyan