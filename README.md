# Programming for Cybersecurity

Small Python, Bash, PowerShell and Go tools I wrote while completing the **Programming for Cybersecurity** path on LetsDefend. Each one automates a task a SOC analyst does by hand: checking logs, looking up IPs and hashes, and watching for suspicious activity.

I also wrote a walkthrough on Medium explaining what each tool does and how it works.

> These scripts are for learning and for use on systems you own or are authorized to monitor. Replace every `MUST_BE_FILLED` placeholder with your own API keys or tokens. Never commit real secrets.

## Tools

### Python
| File | What it does |
|---|---|
| `Python/fim.py` | File integrity monitor: hashes `/etc/passwd` and `/etc/shadow` with SHA-256 and prints a message when one changes |
| `Python/ids.py` | Simple network monitor: reads packets from a raw socket and checks them against an IP blacklist (`iplist.txt`). Needs root |

### Bash
| File | What it does |
|---|---|
| `Bash/abuse.sh` | Gets an AbuseIPDB report for an IP |
| `Bash/apachelog.sh` | Counts Apache access log requests per client IP and request |
| `Bash/authlog.sh` | Shows successful and failed logins for a given IP from `auth.log` |
| `Bash/check_sec_updates.sh` | Checks for security updates and sends a Telegram alert |
| `Bash/failed_login_check.sh` | Finds failed SSH password attempts in `auth.log` and emails an alert |
| `Bash/ports.sh` | Lists listening ports and the process behind each one |

### PowerShell
| File | What it does |
|---|---|
| `Powershell/evt.ps1` | Reads Security event 4624 (logons) for a user in a date range |
| `Powershell/ipcheck.ps1` | Checks IPs on VirusTotal and sends a Telegram alert |
| `Powershell/isslog.ps1` | Parses an IIS W3C log and summarizes client IPs |
| `Powershell/logons.ps1` | Lists currently logged-on users |
| `Powershell/ps_hash_check.ps1` | Hashes running processes and checks them on VirusTotal |
| `Powershell/securestring.ps1` | Stores a password as an encrypted secure string |
| `Powershell/updates.ps1` | Searches for pending Windows updates |
| `Powershell/windows_eventid_tracker.ps1` | Counts selected Security event IDs in the last hour and sends a Telegram alert when a threshold is exceeded |

### Go
| File | What it does |
|---|---|
| `GO/detect_sus_ip.go` | Reads a PCAP file and checks the IPs it finds on VirusTotal |
| `GO/email_analysis.go` | Parses an `.eml` file and checks the subject for suspicious keywords and reads the `Received` headers |
| `GO/ssh_bruteforce_detect.go` | Detects SSH brute-force attempts in a log file |

## Sample data
`sample_phishing.eml`, `sample_traffic.pcap`, `ssh_bruteforce.log` and `iss_w3svc1.log` are synthetic or lab samples for testing the tools. They contain no real user data.

## Usage examples
```bash
python3 Python/fim.py
go run GO/ssh_bruteforce_detect.go ssh_bruteforce.log
go run GO/email_analysis.go sample_phishing.eml
go run GO/detect_sus_ip.go sample_traffic.pcap   # needs a VirusTotal API key
```

## Author
Efe Özel: [LinkedIn](https://www.linkedin.com/in/efeozell) · [Medium](https://medium.com/@efeqozel) · [efeozel.com](https://efeozel.com)
