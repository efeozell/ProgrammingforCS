$securePassword = Read-Host -Prompt "Enter your password" -AsSecureString
$securePassword | ConvertFrom-SecureString | Set-Content mysecurestring.txt
