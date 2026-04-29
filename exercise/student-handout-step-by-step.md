# Student Handout: Detection Engineering Practical (Splunk + Elastic)

## What you are doing
You will investigate a simulated npm supply-chain compromise and build equivalent detections in:
- **Splunk (SPL)**
- **Elastic (Kibana + ES|QL)**

Your goal is to detect the activity, tune your logic, and explain platform tradeoffs.

---

## Scenario summary
Compromised packages were installed, followed by suspicious script execution, outbound C2 traffic, and persistence artifacts.

### Known IOCs for this lab
- Domain: `sfrclak.com`
- IP: `142.11.206.73`
- URL: `http://sfrclak.com:8000/6202033`
- Packages: `axios@1.14.1`, `axios@0.30.4`, `plain-crypto-js@4.2.1`
- Artifacts:
  - macOS: `/Library/Caches/com.apple.act.mond`
  - Windows: `%PROGRAMDATA%\wt.exe`, `%TEMP%\6202033.vbs`, `%TEMP%\6202033.ps1`
  - Linux: `/tmp/ld.py`

---

## Required deliverables (submit all)
1. IOC detections in SPL and ES|QL
2. Behavioral detections in SPL and ES|QL
3. Correlation detection in SPL and ES|QL
4. Kibana evidence (Discover notes/screenshots + rule setup)
5. 1-page comparison: SPL vs ES|QL (precision, performance, maintainability)
6. ATT&CK mapping table

---

## Real threat intel references (with IOC-rich reporting)
Use these for enrichment and ATT&CK justification in your write-up.

- Unit 42, axios supply chain attack:
  - https://unit42.paloaltonetworks.com/axios-supply-chain-attack/
- The DFIR Report, Bumblebee to Akira:
  - https://thedfirreport.com/2025/11/04/from-bing-search-to-ransomware-bumblebee-and-adaptixc2-deliver-akira-2/
- Microsoft Threat Intelligence, WhatsApp malware campaign:
  - https://www.microsoft.com/en-us/security/blog/2026/03/31/whatsapp-malware-campaign-delivers-vbs-payloads-msi-backdoors/
- Cisco Talos, LucidRook malware:
  - https://blog.talosintelligence.com/new-lua-based-malware-lucidrook/
- Google Threat Intelligence, BRICKSTORM campaign:
  - https://cloud.google.com/blog/topics/threat-intelligence/brickstorm-espionage-campaign
- Volexity, Exchange exploitation case study:
  - https://www.volexity.com/blog/2021/03/02/active-exploitation-of-microsoft-exchange-zero-day-vulnerabilities/

Note: these sources are for context and mapping, not required to exactly match this synthetic dataset.

---

## Step-by-step workflow

## Step 1: Open your materials
1. Open `splunk/starter-queries.spl`
2. Open `elastic/esql/starter-queries.esql`
3. Open `kibana/checklist.md`
4. Create a notes doc for answers and evidence

Output to capture:
- Student name/team
- Date/time
- Environment names (Splunk instance + Kibana space)

---

## Step 2: Data familiarization (both platforms)

### 2A) Splunk
1. Search broad sample data:
   - `index=detection_demo | head 50`
2. Identify core fields used for detection:
   - host/user/process/network/file/package fields

### 2B) Kibana Discover
1. Open the detection demo index pattern
2. Inspect sample events and ECS field names

### 2C) Build your field mapping table
Create a small table in your notes:
- `host` ↔ `host.name`
- `user` ↔ `user.name`
- `process_commandline` ↔ `process.command_line`
- `file_path` ↔ `file.path`
- `domain/ip/url` ↔ `domain/destination.ip/url.full`
- `package_name/package_version` ↔ `package.name/package.version`

Output to capture:
- Field mapping table with at least 8 mapped fields

---

## Step 3: IOC detections

### 3A) Run IOC query in Splunk
1. Run IOC starter query from `splunk/starter-queries.spl`
2. Validate hits for domain/IP/URL/packages
3. Record affected hosts and users

### 3B) Run IOC query in ES|QL
1. Run IOC query from `elastic/esql/starter-queries.esql`
2. Confirm equivalent hits

Output to capture:
- First seen timestamp
- Last seen timestamp
- Distinct impacted hosts
- Which IOC types matched

Checkpoint question:
- Are SPL and ES|QL results equivalent? If not, why?

---

## Step 4: Behavioral detections

### 4A) Build behavior logic
Detect this pattern:
- package install/postinstall activity
- interpreter execution (`powershell`, `wscript/cscript`, `python`, `osascript`, `zsh/bash/sh`)

### 4B) Splunk
1. Run behavioral starter SPL
2. Tune to reduce noise (add constraints by parent process, commandline substrings, host role, etc.)
3. Document tuning choices

### 4C) ES|QL
1. Run behavioral ES|QL starter
2. Apply equivalent tuning
3. Compare false positives vs Splunk

Output to capture:
- Final behavioral query (both platforms)
- Why each filter was added
- Before/after result count

---

## Step 5: Persistence artifact detections

### 5A) Splunk
1. Run persistence artifact query
2. Confirm OS-specific artifact paths

### 5B) ES|QL
1. Run persistence artifact query
2. Confirm equivalent findings

Output to capture:
- Artifact path
- Host/user/process
- Timestamp

---

## Step 6: Correlation detection (high-confidence)

Goal: Detect where all 3 occur within the same time window:
1. Compromised package event
2. Suspicious process execution
3. Outbound C2 event

### 6A) Splunk
1. Run correlation starter SPL (30m bucket)
2. Confirm hosts with all three conditions

### 6B) ES|QL
1. Run correlation starter ES|QL
2. Validate equivalent correlated hits

Output to capture:
- Correlated host list
- Window used (e.g., 30m)
- Why this is high confidence

Checkpoint question:
- What breaks if the window is too small or too large?

---

## Step 7: Kibana practical tasks

Use `kibana/checklist.md` and complete every checkbox.

Minimum required:
1. Discover pivot workflow notes:
   - package event → process event → network event
2. ES|QL hunt results saved/exported
3. 3 Elastic Security rules created:
   - IOC rule
   - behavioral rule
   - correlation rule
4. Visual evidence:
   - timeline by host
   - top suspicious processes
   - destination domain/IP chart
   - file artifacts by OS

Output to capture:
- Screenshots or exported results
- Rule names, severities, and short triage guidance

---

## Step 8: ATT&CK mapping
Map your detections to ATT&CK techniques in a table.

Template:
| Detection | Data source | ATT&CK tactic | ATT&CK technique | Why |
|---|---|---|---|---|
| IOC domain/IP | DNS/Proxy | Command and Control | T1071 (or appropriate) | Outbound to known C2 |

Output to capture:
- At least 4 detection-to-ATT&CK mappings

---

## Step 9: Platform comparison write-up (1 page)
Answer clearly:
1. Which platform gave faster query iteration and why?
2. Which platform made correlation easier and why?
3. Which query language was easier to maintain for this use case?
4. What precision/false-positive differences did you observe?
5. Final recommendation for production workflow

Keep it evidence-based, not opinion-only.

---

## Step 10: Final submission checklist
Before submitting, verify:
- [ ] IOC queries completed in SPL + ES|QL
- [ ] Behavioral queries completed in SPL + ES|QL
- [ ] Correlation queries completed in SPL + ES|QL
- [ ] Kibana checklist completed
- [ ] ATT&CK table included
- [ ] 1-page comparison included
- [ ] Evidence attached (screenshots/results)

---

## Time guidance
- Step 1-2: 20 min
- Step 3: 20 min
- Step 4: 30 min
- Step 5: 15 min
- Step 6: 25 min
- Step 7: 25 min
- Step 8-9: 20 min
- Step 10: 5 min

Total: ~160 minutes (~2h 40m)

---

## Troubleshooting hints
- No IOC hits? Recheck index/index pattern and time range.
- Too many behavior hits? Add parent/child process constraints and commandline patterns.
- Correlation empty? Expand window and verify each signal exists independently first.
- SPL and ES|QL differ? Compare field names and null handling.

Good luck. Treat this like a real incident. Clean logic wins.
