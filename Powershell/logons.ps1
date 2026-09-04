
$queryOutput = query user

$LoggedUsers = $queryOutput | ForEach-Object {
    $line = $_ -replace '^>', ''
    if ($line -match '^\s*(?<username>\S+)\s+console') {
        $Matches['username']
    }
}

if (-not $LoggedUsers) {
    Write-Host "No user with an active session via the console was found" -ForegroundColor Yellow
    return
}

Write-Host "Active console users: $($LoggedUsers -join ', ')`n"

$startTime = (Get-Date).AddHours(-24)

try {
    $allEvents = Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4624; StartTime=$startTime} -ErrorAction Stop
} catch {
    Write-Host "Event 4624 not found on last 24 hours"
    return 
}

$logonTypeMap = @{
    2 = "Interactive"
    3 = "Network"
    4 = "Batch"
    5 = "Service"
    7 = "Unlock"
    8 = "NetworkCleartext"
    9 = "NewCredentials"
    10 = "RemoteInteractive (RDP)"
    11 = "CachedInteractive"
}

#Find last login for each user
foreach ($username in $LoggedUsers) {

    $matchedEvent = $null

    foreach ($event in $allEvents) {
        $xml = [xml]$event.ToXml()
        $eventUsername = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq 'TargetUserName'}).'#text'

        if ($eventUsername -eq $username) {
            $logonType = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq 'LogonType'}).'#text'

            $matchedEvent = [PSCustomObject]@{
                Username = $username
                LogonType = $logonType
                LogonTypeDesc = $logonTypeMap[[int]$logonType]
                TimeCreated = $event.TimeCreated
            }
            break
        }
    }

    if ($matchedEvent) {
        Write-Host "[$username] Last Logon: $($matchedEvent.TimeCreated) - LogonType: $($matchedEvent.LogonType) ($($matchedEvent.LogonTypeDesc))"

        if ($matchedEvent.LogonType -in @(3, 10)) {
            Write-Host "  -> [ALERT] The user appears in the console, but the last login type '$($matchedEvent.LogonTypeDesc)' - This might be inconsistent!" -ForegroundColor Red
        }

    } else {
        Write-Host "[$username] Not found event id 4624 on last 24 hours"
    }
}