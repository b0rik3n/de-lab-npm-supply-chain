# Extended Student Handout
## Detection Engineering Practical, npm Supply-Chain Compromise

## 1) Why this lab exists
This lab is designed to train you to think like a detection engineer, not just a query author.

A detection engineer’s job is to:
- turn threat information into measurable telemetry logic,
- test that logic across different platforms,
- tune detections to reduce false positives,
- and communicate detection quality clearly.

In this exercise, you will do that work in both **Splunk (SPL)** and **Elastic (Kibana + ES|QL)** using the same scenario and dataset.

---

## 2) Lab objective
You will build equivalent detections in two platforms and compare tradeoffs:
- precision,
- performance,
- and maintainability.

You are expected to show your reasoning at each step.

---

## 3) Scenario context
A supply-chain compromise impacted npm package installs on developer endpoints.
After install, suspicious script execution occurred, followed by outbound C2 traffic and host artifacts consistent with persistence.

### IOC set for this lab
- Domain: `sfrclak.com`
- IP: `142.11.206.73`
- URL: `http://sfrclak.com:8000/6202033`
- Compromised packages:
  - `axios@1.14.1`
  - `axios@0.30.4`
  - `plain-crypto-js@4.2.1`
- Host artifacts:
  - macOS: `/Library/Caches/com.apple.act.mond`
  - Windows: `%PROGRAMDATA%\wt.exe`, `%TEMP%\6202033.vbs`, `%TEMP%\6202033.ps1`
  - Linux: `/tmp/ld.py`

---

## 4) Expected deliverables
You must submit:
1. IOC detections in SPL and ES|QL.
2. Behavioral detections in SPL and ES|QL.
3. Correlation detections in SPL and ES|QL.
4. Kibana investigation evidence.
5. A one-page platform comparison.
6. ATT&CK mapping table.

Optional bonus:
- a short “production hardening” section describing alert tuning and deployment approach.

---

## 5) Materials you must open first
- `splunk/starter-queries.spl`
- `elastic/esql/starter-queries.esql`
- `kibana/checklist.md`
- `data/events.jsonl` (reference)

Create a notebook or markdown notes file with these sections:
- Environment
- Field mapping
- IOC detection
- Behavioral detection
- Correlation detection
- Kibana evidence
- ATT&CK mapping
- SPL vs ES|QL comparison
- Final conclusions

---

## 6) Step-by-step workflow (very detailed)

## Step 0, Environment validation
### Goal
Confirm your lab environment is correct before doing analysis.

### Actions
1. Confirm your Splunk index is available and populated (expected index: `detection_demo`).
2. Confirm your Elastic index pattern resolves events (e.g., `detection_demo_*`).
3. Set time range in both tools to include the event timestamps in the dataset.
4. Test with a broad query in each platform.

### Why this matters
Most failed detections are not bad logic. They are wrong time range, wrong index, or field mismatch.

### Record
- Splunk instance name
- Kibana space/index pattern
- Time range used

---

## Step 1, Data familiarization and schema mapping
### Goal
Understand how equivalent facts are represented in each platform.

### Splunk actions
1. Run:
   - `index=detection_demo | head 50`
2. Identify fields by category:
   - identity: host/user
   - process: name/parent/commandline
   - network: domain/ip/url
   - file: path/action
   - package: name/version/action

### Elastic actions
1. Open Kibana Discover.
2. Filter to the lab dataset.
3. Inspect ECS field structure for the same categories.

### Build a crosswalk table
At minimum map:
- `host` ↔ `host.name`
- `user` ↔ `user.name`
- `process_name` ↔ `process.name`
- `parent_process_name` ↔ `process.parent.name`
- `process_commandline` ↔ `process.command_line`
- `file_path` ↔ `file.path`
- `domain` ↔ `domain`
- `destination_ip`/`ip` ↔ `destination.ip`
- `url` ↔ `url.full`
- `package_name` ↔ `package.name`
- `package_version` ↔ `package.version`

### Why this matters
Detection parity fails when schema assumptions differ. Cross-platform mapping is foundational.

### Record
- final mapping table (8+ fields)
- unknown or nullable fields
- field normalization notes

---

## Step 2, IOC detections
### Goal
Detect known indicators quickly and accurately in both stacks.

### Splunk actions
1. Run IOC starter query from `splunk/starter-queries.spl`.
2. Validate each IOC category independently:
   - domain
   - IP
   - URL
   - package@version
3. Add summary stats for first seen / last seen / impacted hosts.

### ES|QL actions
1. Run IOC starter query from `elastic/esql/starter-queries.esql`.
2. Confirm equivalent results and fields.
3. Ensure output includes timestamp and host context.

### Tuning guidance
- Keep IOC rules strict, but preserve context fields for triage.
- Avoid over-aggregation that hides event-level details.

### Record
- distinct hosts/users impacted
- first and last IOC event timestamps
- IOC category hit counts

### Validation prompt
If SPL and ES|QL differ, identify exactly where:
- field naming,
- null handling,
- case sensitivity,
- parser behavior.

---

## Step 3, Behavioral detection logic
### Goal
Detect suspicious execution behavior independent of static IOC match.

### Behavioral pattern
Build detections for:
1. package install or postinstall context,
2. interpreter execution (`powershell`, `wscript/cscript`, `python`, `osascript`, `zsh/bash/sh`),
3. suspicious commandline fragments (`ExecutionPolicy Bypass`, `setup.js`, known dropper path patterns).

### Splunk actions
1. Run starter behavioral query.
2. Tune in stages:
   - Stage A: broad behavior logic
   - Stage B: add parent-process constraints
   - Stage C: add commandline constraints
   - Stage D: remove obvious benign patterns
3. Measure result volume after each stage.

### ES|QL actions
1. Mirror the same staged logic in ES|QL.
2. Keep parity with SPL intent.
3. Compare output set and false positives.

### Why this matters
IOC detections break when indicators rotate. Behavioral logic is more resilient.

### Record
- final SPL and ES|QL behavior queries
- each tuning step and rationale
- before/after event counts

---

## Step 4, Persistence artifact detections
### Goal
Find host artifacts that support a higher-confidence compromise story.

### Splunk actions
1. Run file artifact query from starter pack.
2. Validate path matches by platform.

### ES|QL actions
1. Run corresponding ES|QL artifact query.
2. Validate matching host and timeline.

### Record
For each hit:
- timestamp
- host
- user
- process
- artifact path

### Analyst interpretation
Artifacts are high-value triage evidence. They strengthen confidence beyond single network or package events.

---

## Step 5, Correlation detection
### Goal
Create a high-confidence detection requiring three signals in one time window:
1. compromised package event,
2. suspicious process event,
3. outbound C2 signal.

### Default window
Start with 30 minutes. Then test 15 and 60 to observe detection sensitivity.

### Splunk actions
1. Run starter correlation SPL.
2. Verify all three conditions are present.
3. Confirm host-level grouping and time bucket behavior.

### ES|QL actions
1. Run starter correlation ES|QL.
2. Confirm equivalent host/window results.
3. Compare parity vs SPL.

### Why this matters
Correlation raises signal quality and reduces single-event false positives.

### Record
- correlated host list
- selected time window and reason
- result differences by window size

---

## Step 6, Kibana practical execution
### Goal
Demonstrate analyst workflow and operationalization in Elastic.

### Required tasks
1. In Discover, pivot through:
   - package event → process event → network event.
2. Run ES|QL IOC, behavioral, and correlation hunts.
3. Create three Elastic Security rules:
   - IOC rule
   - behavioral rule
   - correlation rule
4. Capture required visual evidence:
   - timeline by host
   - suspicious process chart
   - destination domain/IP chart
   - artifact distribution by OS

### Record
- rule names
- severities
- schedules
- investigation notes/guidance
- screenshots or exported result sets

---

## Step 7, ATT&CK mapping
### Goal
Map your detections to ATT&CK with clear justifications.

Use this template:

| Detection | Data source | ATT&CK tactic | ATT&CK technique | Evidence-based rationale |
|---|---|---|---|---|
| C2 domain/IP detection | DNS/Proxy | Command and Control | T1071 (example) | Outbound comms to known C2 infrastructure |

### Record
- at least 4 mappings
- one concrete rationale sentence per mapping

---

## Step 8, SPL vs ES|QL comparison report
### Goal
Produce an evidence-based cross-platform analysis.

Answer all:
1. Which platform enabled faster hunting iteration and why?
2. Which platform made correlation simpler and why?
3. Which query language is more maintainable for your team?
4. What precision differences did you observe?
5. What performance differences did you observe?
6. What is your recommendation for production use in this scenario?

### Quality requirements
- Use measured evidence (counts, query behavior, screenshots).
- Avoid generic claims.
- Tie conclusions to your actual results.

---

## Step 9, Final QA before submission
Check each item:
- [ ] IOC detections complete in both SPL and ES|QL
- [ ] Behavioral detections complete in both SPL and ES|QL
- [ ] Correlation detections complete in both SPL and ES|QL
- [ ] Kibana checklist completed
- [ ] ATT&CK mapping included
- [ ] One-page comparison included
- [ ] Evidence attached
- [ ] Queries readable and commented

---

## 7) Recommended timeline
- Environment + schema mapping: 25 minutes
- IOC detection: 20 minutes
- Behavioral detection: 35 minutes
- Artifact detection: 15 minutes
- Correlation detection: 30 minutes
- Kibana tasks: 25 minutes
- ATT&CK + report writing: 25 minutes
- Final QA and packaging: 10 minutes

Total: ~3 hours 5 minutes

---

## 8) Troubleshooting guide

### Issue: no results at all
- Verify index/index pattern and time range first.
- Confirm data was ingested.

### Issue: IOC results in one platform only
- Compare field names and exact value formatting.
- Check null handling and string matching semantics.

### Issue: too many behavioral hits
- Add parent-process constraints.
- Require stronger commandline context.
- Scope to intended endpoint population.

### Issue: correlation empty
- Confirm each signal independently before correlation.
- Increase time window temporarily.
- Verify grouping key (host identity consistency).

### Issue: query parity mismatch
- Re-check schema crosswalk.
- Compare operators and casting behavior.

---

## 9) Optional extension tasks (advanced)
1. Create a weighted risk score model:
   - package hit = low-medium,
   - process behavior = medium,
   - C2 + artifact = high.
2. Add allowlist logic for known benign admin scripts.
3. Add detection metadata fields:
   - confidence,
   - severity,
   - triage owner,
   - ATT&CK tags.
4. Draft a production deployment plan with rollback.

---

## 10) Submission packaging suggestion
```
submission/
  queries/
    spl/
      ioc.spl
      behavior.spl
      correlation.spl
    esql/
      ioc.esql
      behavior.esql
      correlation.esql
  evidence/
    kibana-discover-*.png
    correlation-results-*.csv
  report/
    comparison.md
    attack-mapping.md
```

---

## Final note
Strong detection engineering work is clear, testable, and explainable.
If someone else cannot run your logic and reproduce your conclusions, it is not finished.

Be precise. Be evidence-driven. Keep it operational.