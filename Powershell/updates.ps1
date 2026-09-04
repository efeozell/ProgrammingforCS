
$updateSession = New-Object -ComObject Microsoft.Update.Session
$updateSearcher = $updateSession.CreateUpdateSearcher()

$updateToDownload = New-Object -ComObject Microsoft.Update.UpdateColl

$searchResult = $updateSearcher.Search("IsInstalled=0 and Type='Software'")

if ($searchResult.Updates.Count -eq 0) {
    Write-Output "No Updates to install"
} else {
    Write-Output " $(searchResult.Updates.Count) updates to install."

    $searchResult.Updates | ForEach-Object {
        Write-Output ("Title: " + $_.Title)
        Write-Output ("Description: " + $_.Description)
        Write-Output ("IsDownload: " + $_.IsDownloaded)
        Write-Output ("------------------")

    }
}