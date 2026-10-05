# Detection Rules

Original Sigma detection rules for common Windows attacker behaviors, mapped to MITRE ATT&CK. Authored by Donn Gordon.

These rules are starting points. Review, test and tune them in your own environment before using them in production.

## Rules

| Rule | ATT&CK | Log source | Required telemetry |
|---|---|---|---|
| [`powershell_encoded_command.yml`](sigma-rules/powershell_encoded_command.yml) | T1059.001 | Process creation | Sysmon Event ID 1 or Windows Security Event ID 4688 with command-line auditing |
| [`lsass_access_suspicious_process.yml`](sigma-rules/lsass_access_suspicious_process.yml) | T1003.001 | Process access | Sysmon Event ID 10 |
| [`remote_service_creation_lateral_movement.yml`](sigma-rules/remote_service_creation_lateral_movement.yml) | T1021.002, T1569.002 | Process creation | Sysmon Event ID 1 or Windows Security Event ID 4688 with command-line auditing |

## Log sources

- **Sysmon** (Event IDs 1 and 10) for process creation and process access.
- **Windows Security log** (Event ID 4688), with "Include command line in process creation events" enabled.
- **PowerShell logging** (Event ID 4104, ScriptBlock logging) for follow-on rules that inspect script content.

## Usage

Convert a rule to your SIEM's query language with [sigma-cli](https://github.com/SigmaHQ/sigma-cli):

```bash
pip install sigma-cli
sigma convert -t splunk -p splunk_windows sigma-rules/powershell_encoded_command.yml
```

Other backends include Elasticsearch/Lucene and Microsoft Sentinel (KQL).

## Tuning notes

- **Encoded PowerShell:** administration and deployment tools often use `-EncodedCommand`. Exclude known parent processes and service accounts.
- **LSASS access:** EDR and security agents legitimately read LSASS. Add your vendor's installation paths to the filter.
- **Remote service creation:** IT teams use `sc.exe` against remote hosts for deployments. Allow-list known admin hosts and accounts.

## Roadmap

- Rules for script block content (download cradles, in-memory execution)
- Persistence and command-and-control detections
- Cloud and container telemetry

## Author

Donn Gordon
