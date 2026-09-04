$username = "efe"
$startDate = Get-Date "2026/01/01 00:00:00"
$endDate = Get-Date "2026/08/28 23:59:59"

try {

    $events = Get-WinEvent -FilterHashTable @{
    LogName = 'Security'
    ID = 4624
    StartTime = $startDate
    EndTime = $endDate
    } -ErrorAction Stop

} catch {
    Write-Host "No events matching the specified criteria were found, or an error has occurred."
    return
}

foreach ($event in $events) {
    $xml = [xml]$event.ToXml()
    $eventUsername = $xml.Event.EventData.Data | Where-Object { $_.Name -eq 'TargetUserName' } | Select-Object -ExpandProperty '#text'

    if ($eventUsername -eq $username) {
        Write-Host "User: $eventUsername, Login Date: $($event.TimeCreated)"
    }
}

