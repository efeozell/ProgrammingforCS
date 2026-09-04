$BotToken = "MUST_BE_FILLED"
$ChatID = "MUST_BE_FILLED"
$Url = "https://api.telegram.org/bot$BotToken/sendMessage"


if ([string]::IsNullOrWhiteSpace($BotToken)) {
    Write-Host "[HATA] BOT_TOKEN must be fill. Script stopping"
    exit 1
}

$lastHour = (Get-Date).AddHours(-1)

$eventLimits = @{4625=10; 4648=5; 4703=3; 1102=1; 7045=2}

Write-Host "=====================================" -ForegroundColor Cyan
Write-Host "Control Starting: $(Get-Date)" -ForegroundColor Cyan
Write-Host "Time period: $lastHour - $(Get-Date)" -ForegroundColor Cyan
Write-Host "=====================================" -ForegroundColor Cyan

foreach ($entry in $eventLimits.GetEnumerator()) {
    $id = $entry.key
    $limit = $entry.Value

    Write-Host "`n[CONTROL] Event ID: $id | Threshold: $limit"

    try {
        $events = Get-WinEvent -FilterHashtable @{LogName='Security'; ID=$id; StartTime=$lastHour} -ErrorAction Stop
    } catch {
        Write-Host "  -> Result: NO incidents were found for this ID in the last hour." -ForegroundColor Yellow
        continue
    }

    $count = $events.Count
    Write-Host " -> Findings total events: $count"

    if ($events.Count -gt $limit) {

        Write-Host " -> The threshold has been crossed ($count > $limit). Alert sending... " -ForegroundColor Red

        $message = "🚨 *Alert: Event ID $id Threshold Exceeded*`n" +
        "Count: $($events.Count) (limit: $limit)`n" +
        "System: $($events[0].MachineName)`n" +
        "Last occurrence: $($events[0].TimeCreated)"

        $body = @{
            chat_id    = $ChatID
            text       = $message
            parse_mode = "Markdown"
        }

        try {
            $response = Invoke-RestMethod -Uri $Url -Method Post -Body $body -ErrorAction Stop | Out-Null
            if ($response.ok -eq $true) {
                Write-Host " -> Telegram alert was sent successfully" -ForegroundColor Green
            } else {
                Write-Host " -> Telegram API 'ok:false' responsed. Respınse: $($response | ConvertTo-Json -Compress)" -ForegroundColor Red
            }
        } catch {
            Write-Host "Telegram message wasnt sent (Event ID $id): $($_.Exception.Message)"
        }
    } else {
        Write-Host " -> Threshold Exceeded ($count <= $limit). Alert not sending" -ForegroundColor DarkGray
    }
}

Write-Host "`n=====================================" -ForegroundColor Cyan
Write-Host "Control Completed: $(Get-Date)" -ForegroundColor Cyan
Write-Host "=====================================" -ForegroundColor Cyan


# $body = @{
#    chat_id    = $ChatID
#    text       = "TESTNOW03:36"
#    parse_mode = "Markdown"
# }

#Invoke-RestMethod -Uri $Url -Method Post -Body $body -ErrorAction Stop | Out-Null