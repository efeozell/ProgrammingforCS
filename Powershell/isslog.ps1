$filePath = "iss_w3svc1.log"

$allLines = Get-Content -Path $filePath

$fieldsLine = $allLines | Where-Object { $_ -match  "^#Fields:"} | Select-Object -First 1

if (-not $fieldsLine) {
	Write-Error "#Fields line not found"
	return
}

$ipFieldIndex = $fieldsLine.Split(' ').IndexOf('c-ip') - 1

if ($ipFieldIndex -lt 0) {
	Write-Error "'c-ip' field not found"
	return
}

$logContent = $allLines | Where-Object { $_ -notmatch "^#" -and $_.Trim() -ne "" }

$ipCount = @{}
foreach ($line in $logContent) {
	$fields = $line.Split(' ')
	if ($fields.Length -le $ipFieldIndex) { continue }

	$ip = $fields[$ipFieldIndex]
	if ($ipCount.ContainsKey($ip)) {
		$ipCount[$ip]++
	}else {
		$ipCount[$ip] = 1
	}
}

$ipCount
