$BotToken = "MUST_BE_FILLED"
$ChatID = "MUST_BE_FILLED"
$Url = "https://api.telegram.org/bot$BotToken/sendMessage"

$VTApiKey = "MUST_BE_FILLED"


Write-Host "=====================================" -ForegroundColor Cyan
Write-Host "IP Check Starting: $(Get-Date)" -ForegroundColor Cyan
Write-Host "=====================================" -ForegroundColor Cyan

if ([string]::IsNullOrWhiteSpace($BotToken)) {
    Write-Host "[Alert] TELEGRAM_BOT_TOKEN must be setting" -ForegroundColor Yellow
}
if ([string]::IsNullOrWhiteSpace($VTApiKey)) {
    Write-Host "[Alert] VT_API_KEY must be setting" -ForegroundColor Yellow
}

#This function take one parameter message and sent post request with telegram api
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

#this function take two parameter ip and username and with these parameters send get request to virustotal api with found ip address
function IpCheck($ip, $userName) {
    if ([string]::IsNullOrWhiteSpace($VTApiKey)) {
        Write-Host "VT_API_KEY must be filled" -ForegroundColor Yellow
        return
    }

    $headers = @{
        "x-apikey" = $VTApiKey
    }

    try {
        $vtResponse = Invoke-RestMethod -Uri "https://www.virustotal.com/api/v3/ip_addresses/$ip" -Headers $headers -Method Get -ErrorAction Stop
    } catch {
        Write-Host "The VirusTotal query failed ($ip): $($_.Exception.Message)" -ForegroundColor Yellow
        return
    }

    $stats = $vtResponse.data.attributes.last_analysis_stats
    $malicious  = $stats.malicious
    $suspicious = $stats.suspicious
    $harmless   = $stats.harmless
    $undetected = $stats.undetected

    Write-Output "IP $ip - Malicious: $malicious, Suspicious: $suspicious, Harmless: $harmless, Undetected: $undetected"

    # Threshold: If one or more engines are classified as ‘malicious’ or ‘suspicious’, an alarm is triggered
    if (($malicious + $suspicious) -gt 0) {
        $msg = "🚨 *Malicious IP Detected*`n" +
               "User: $userName`n" +
               "IP: $ip`n" +
               "VirusTotal: $malicious malicious / $suspicious suspicious (of $($malicious+$suspicious+$harmless+$undetected) engines)`n" +
               "Link: https://www.virustotal.com/gui/ip-address/$ip"

        Write-Output "IP address $ip has been marked as malicious!"
        Send-TelegramAlert $msg
    } else {
        Write-Output "IP address $ip has been marked as clean."
    }
}

try {
    $events = Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4624; StartTime=(Get-Date).AddHours(-1)}
} catch {
    Write-Host "`n[RESUTL] No 4624 (successful login) events were found in the last hour." -ForegroundColor Yellow
    Write-Host "Process Completed: $(Get-Date)" -ForegroundColor Cyan
    return
}

#This foreach loop take event found with Get-WinEvent and with this parsed IP Address and with these parsed ip addresses check malicious or not with IpCheck function
foreach ($event in $events) {
    $eventXML = [xml]$event.ToXml()
    $ipAddress = $eventXML.Event.EventData.Data | Where-Object {$_.Name -eq 'IpAddress'} | Select-Object -ExpandProperty '#text'
    $userName  = $eventXML.Event.EventData.Data | Where-Object {$_.Name -eq 'TargetUserName'} | Select-Object -ExpandProperty '#text'

    try {
        $ipBytes = [System.Net.IPAddress]::Parse($ipAddress).GetAddressBytes()

        if ($ipBytes[0] -eq 10) {
            continue
        }
        elseif ($ipBytes[0] -eq 172 -and $ipBytes[1] -ge 16 -and $ipBytes[1] -le 31) {
            continue
        }
        elseif ($ipBytes[0] -eq 192 -and $ipBytes[1] -eq 168) {
            continue
        }
        else {
            Write-Output "User $userName has logged in from external IP address $ipAddress"
            IpCheck $ipAddress $userName
        }
    }
    catch {
        continue
    }
}

Write-Host "`n=====================================" -ForegroundColor Cyan
Write-Host "Summary" -ForegroundColor Cyan
Write-Host "Total number of entries : $($events.Count)"
Write-Host "Total External IP : $externalCount"
Write-Host "Controlled by VT : $checkedCount"
Write-Host "Process Completed: $(Get-Date)" -ForegroundColor Cyan
Write-Host "=====================================" -ForegroundColor Cyan
