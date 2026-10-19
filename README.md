# Splunk Brute-Force Detection Lab

## Objective
Detect a brute-force authentication pattern (repeated failed logons followed by a successful logon) using Windows Security Event Logs ingested into Splunk, and map the activity to the MITRE ATT&CK framework.

## Environment
- **Host:** Windows 11 laptop (local)
- **SIEM:** Splunk Enterprise (Free license), local installation
- **Log source:** Windows Security Event Log, collected via `inputs.conf` (`WinEventLog://Security`)
- **Simulated activity:** Manually triggered failed logon attempts at the Windows lock screen, followed by a successful logon

## Methodology

**1. Generated test data**
Locked the workstation and entered the wrong password 5 times, then the correct password on the 6th attempt, producing Event ID 4625 (failed logon) and 4624 (successful logon) entries in the Security log.

**2. Initial search**
Queried raw 4625 events to confirm the failed logon attempts were being logged.
→ `01-raw-search-failed-logons.png`

**3. First aggregation — noise identified**
Grouped failed logons by account using `stats count by Account_Name`. This surfaced the machine account (`BRKCIVAN$`) rather than the interactive user account, and didn't yet isolate genuine user-driven events from background activity.
→ `02-initial-stats-by-account.png`

**4. Isolated genuine user authentication events**
A time-sorted view of all 4624/4625 events revealed frequent background `SYSTEM` logons (Logon Type 5) unrelated to the test. Filtered to Logon Type 2 (interactive) and 7 (unlock) to isolate real user authentication activity, revealing the 5 failed attempts followed by a successful unlock.
→ `03-time-sorted-logon-type-filtered.png`

**5. Duplicate event discovery**
Running `stats` on the filtered data initially showed 5 failed attempts but **2** successful logons, not 1. Investigation showed Windows generated two 4624 events (Logon Type 7) within the same millisecond for a single unlock action.
→ `04-stats-before-dedup.png`

**6. Deduplication and final result**
Applied `dedup _time EventCode Logon_Type` to collapse duplicate events, producing an accurate count: **5 failed attempts → 1 successful logon**, within a 46-second window.
→ `05-stats-final-deduped.png`

## Detection Queries
See [`queries/detection-queries.txt`](queries/detection-queries.txt) for all 5 queries used, in order.

Final detection query:
```spl
index=main source="WinEventLog:Security" (EventCode=4625 OR EventCode=4624) (Logon_Type=2 OR Logon_Type=7)
| dedup _time EventCode Logon_Type
| stats count(eval(EventCode=4625)) as failed_attempts, count(eval(EventCode=4624)) as successful_logon
```

## Findings
| Metric | Value |
|---|---|
| Failed logon attempts | 5 |
| Successful logons (deduplicated) | 1 |
| Time window | 46 seconds |
| Logon types | 2 (Interactive), 7 (Unlock) |

## MITRE ATT&CK Mapping
**T1110.001 – Brute Force: Password Guessing**
Repeated authentication attempts with varying credentials on a single account, followed by a successful logon, is consistent with manual password-guessing behavior.

## Lessons Learned
- Raw SIEM data is noisy: background `SYSTEM` account activity and duplicate OS-generated events can inflate detection counts if not filtered.
- Logon Type is a critical field for isolating genuine interactive user activity from service/system noise.
- Deduplication logic is necessary when a single real-world action (e.g., an unlock) generates multiple log entries.
