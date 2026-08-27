# Detection\-as\-Code Architecture

# 1. Purpose and Scope

This document defines a Detection-as-Code (DaC) architecture that treats detection logic the same way software engineering treats application code: version-controlled, peer-reviewed, automatically tested, and deployed through a controlled pipeline. The architecture is designed so any future rule language (KQL-native, Splunk SPL-native, Suricata, YARA-L) can be plugged in without redesigning the pipeline.

# 2. High-Level Architecture

```text
┌──────────────────────────────────────────────────────────────────────────────┐
│                                  RULE LAYER                                   │
│              Sigma YAML rule + metadata + ATT&CK mapping + fixtures           │
│                        status: experimental | test | stable                   │
└──────────────────────────────────────────────────────────────────────────────┘
                                        │
                                        │ git add / commit / push
                                        ▼
┌──────────────────────────────────────────────────────────────────────────────┐
│                            REPOSITORY LAYER (Git)                             │
│                 detections/ | tests/ | mappings/ | pipelines/                 │
│                                docs/ | tools/...                              │
└──────────────────────────────────────────────────────────────────────────────┘
                                        │
                                        │ PR trigger
                                        ▼
┌──────────────────────────────────────────────────────────────────────────────┐
│                                CODE GATE                                      │
│           rule validator (schema, syntax, ATT&CK mapping)                     │
│                            + unit test                                        │
└──────────────────────────────────────────────────────────────────────────────┘
                                        │
                                        │ pass
                                        ▼
┌──────────────────────────────────────────────────────────────────────────────┐
│                                  REVIEW                                       │
│                     human approval / logic + risk check                       │
└──────────────────────────────────────────────────────────────────────────────┘
                                        │
                                        │ approved
                                        ▼
┌──────────────────────────────────────────────────────────────────────────────┐
│                                CI/CD LAYER                                    │
│              merge -> build -> convert -> package -> sign/checksum            │
│                          -> publish to registry                               │
└──────────────────────────────────────────────────────────────────────────────┘
                                        │
                                        │ deploy job
                                        ▼
┌──────────────────────────────────────────────────────────────────────────────┐
│                             DEPLOYMENT LAYER                                  │
│                 single deploy, full site (no canary/staged)                   │
│              SIEM routes by rule "status" field, no redeploy needed:          │
│         status: test   -> monitor only, not routed to analyst queue           │
│         status: stable -> full routing, live case/ticket/escalation           │
└──────────────────────────────────────────────────────────────────────────────┘
                                        │
                                        │ telemetry
                                        ▼
┌──────────────────────────────────────────────────────────────────────────────┐
│                       MONITORING & GOVERNANCE LAYER                           │
│              health dashboard | FP tracking | ATT&CK heatmap                  │
│                   audit trail | rule retirement workflow                      │
└──────────────────────────────────────────────────────────────────────────────┘
                                        │
                                        │ scheduled job: bot pulls metrics
                                        │ (FP rate, alert volume, TP/FP feedback)
                                        ▼
┌──────────────────────────────────────────────────────────────────────────────┐
│                        OPERATIONAL GATE (automated)                           │
│           bot generates report -> opens PR "promote status"                   │
└──────────────────────────────────────────────────────────────────────────────┘
                                  │                     │
                            pass  │                     │  fail
                                  ▼                     ▼
              ┌───────────────────────────┐   ┌───────────────────────────┐
              │  PROMOTE: test -> stable    │   │       test        │
              │  review PR -> merge          │   │  back to Rule layer to     │
              │  status -> stable             │   │  tune logic, re-PR         │
              │  (rule stays deployed,        │   │  (dropped from live        │
              │   routing only changes)       │   │   routing, back to monitor)│
              └───────────────────────────┘   └───────────────────────────┘
```


# 3. Repository Tree

```
detection-as-code/
├── rules/                          # SIGMA-STANDARD: production detections
│   ├── windows/
│   │   ├── process_creation/
│   │   ├── registry/
│   │   ├── network_connection/
│   │   ├── image_load/
│   │   └── file_event/
│   ├── linux/
│   │   ├── process_creation/
│   │   └── auditd/
│   ├── macos/
│   ├── cloud/
│   │   ├── aws/
│   │   ├── azure/
│   │   ├── gcp/
│   │   └── m365/
│   ├── network/
│   │   ├── firewall/
│   │   ├── proxy/
│   │   └── dns/
│   ├── application/
│   │   ├── web/
│   │   └── database/
│   └── identity/
│       ├── okta/
│       └── azuread/
│
├── rules-emerging-threats/         # SIGMA-STANDARD: time-boxed, campaign/CVE/APT
│   └── 2026/
│       └── <threat-or-cve-slug>/
│
├── rules-threat-hunting/           # SIGMA-STANDARD: broad, high-FP
│   └── windows/...
│
├── rules-placeholder/              # SIGMA-STANDARD: rule customer
│   └── ...                          
│
├── rules-deprecated/               # SIGMA-STANDARD: retired/superseded rules kept for audit trail
│
├── tests/                          
│   ├── unit/
│   │   └── windows/
│   │       └── process_creation/
│   │           └── <rule-id>.test.yml
│   └── fixtures/
│       └── windows/
│           └── process_creation/
│               └── <rule-id>/
│                   ├── event_01.json
│                   └── event_02.json
│
├── config/                         
│   ├── backends/
│   │   ├── alethea.yml
│   │   ├── splunk.yml
│   │   ├── elastic.yml
│   │   ├── sentinel.yml
│   │   └── qradar.yml
│   └── pipelines/                  # field-mapping / log-source pipelines
│       ├── windows-logsource.yml
│       └── cloud-logsource.yml
│
├── mappings/                       
│   ├── mitre-attack-navigator/
│   │   └── coverage-layer.json
│   └── data-source-to-rule.csv
│
├── metrics/                       
│   ├── daily/
│   │   └── 2026-08-10.csv
│   │   └── 2026-08-11.csv
│   │   └── ...
│   └── promotion-eligible/
│   │   └── ...
├── docs/
│   ├── architecture/
│   │   └── detection-as-code-architecture.md 
│   │   └── .....
│   ├── conventions/
│   │   ├── naming-convention.md
│   │   ├── rule-lifecycle.md
│   │   └── contribution-guide.md
│   └── runbooks/
│       └── <rule-id>-response-guide.md
│
├── .github/                        # or .gitlab-ci/
│   ├── workflows/
│   │   ├── lint-and-validate.yml
│   │   ├── unit-test.yml
│   │   ├── convert-and-deploy.yml
│   │   └── attack-coverage-report.yml
│   └── CODEOWNERS
│
├── scripts/                        # tools 
│   ├── validate_sigma.py
│   ├── 
│   └── 
│
├── .sigma/                         # local tool config
│   └── sigma-plugins.yml
│
├── CHANGELOG.md
├── CONTRIBUTING.md
└── README.md
```

## 3.1. Folder Responsibilities

| **Folder** | **Responsibility** |
| --- | --- |
| `rules/` | Are threat agnostic, their aim is to detect a behavior or an implementation of a technique or procedure that was, can or will be used by a potential threat actor. |
| `rules-emerging-threats/` | Time-boxed rules tied to a CVE, campaign, or malware family; expected to be reviewed/retired periodically. |
| `rules-threat-hunting/` | Broad-scope, higher-noise rules meant as hunt starting points, not auto-alerting. |
| `rules-placeholder/` | The rules available in this folder, are flexible detection templates that can be customized for your environments or use cases. |
| `rules-deprecated/` | Retired rules preserved for audit/history rather than deleted, matching Sigma's practice of `status: deprecated`. |
| `tests/` | Houses unit test definitions and log fixtures (positive/negative). |
| `docs/` | Architecture decisions, conventions, and per-rule response runbooks. |
| `.github/workflows/` | CI/CD: linting, schema validation, unit tests, conversion, deployment, coverage reporting. |
| `scripts/` | Helper tooling wrapping for validation/conversion/reporting. |


## 3.2. Rule Naming Convention

File naming: `<logsource>_<short_description>.yml`

Example:

- `proc_creation_win_mimikatz_command_line.yml`
- `aws_cloudtrail_iam_policy_privesc.yml`

Rules:

- All lowercase, underscore-separated, no spaces.
- Prefix reflects log source category, matching folder placement (`proc_creation_`, `registry_`, `net_connection_`, `file_event_`, `image_load_`, `aws_cloudtrail_`, etc.)
- Description should be specific enough to distinguish from siblings but not restate the full title.


## 3.3. Rule Organization Strategy

- Grouping: primarily by log source (OS/platform → category), secondarily by ATT&CK tactic/technique via the tags field rather than by directory.
- Rationale: a technique like Credential Dumping can manifest in process\_creation, file\_event, and registry logsources simultaneously - forcing an ATT&CK-based folder structure would fragment closely related detections that share a pipeline/backend, and would require duplicating rules across technique folders. Metadata-based tagging (tags: \[attack.t1003, attack.credential-access\]) avoids this while still enabling technique-level views via the mappings/ coverage layer.

Rule status (`status` field, per spec - do not invent new values):

| **Status** | **Meaning** | **Folder** |
| --- | --- | --- |
| `experimental` | n experimental rule that could lead to false positives results or be noisy, but could also identify interesting events. | `rules/` |
| `test` | a mostly stable rule that could require some slight adjustments depending on the environment. | `rules/` |
| `stable` | the rule is considered as stable and may be used in production systems or dashboards. | `rules/` |
| `deprecated` | the rule is replaced or covered by another one. The link is established by the `related` field. | `rules-deprecated/` |
| `unsupported` | the rule cannot be use in its current state (old correlation format, custom fields) |  |

## 3.4. Test organization Strategy

**Structure**: tests live in a parallel tree mirroring `rules/`, keyed by rule `id` (not filename, since filenames can change but `id` is stable):

```
tests/unit/windows/process_creation/<rule-id>.test.yml
tests/fixtures/windows/process_creation/<rule-id>/*.* (*.json)
```


`<rule-id>.test.yml`** example**:

```
rule_id: bd5b7103-d118-4331-b5b2-12a8b8861741   # bắt buộc, khớp field `id` của rule
backend: sigma-unit-test                         # tùy chọn - metadata, xem mục 4.2
description: >                                   # tùy chọn
  Mô tả ngắn mục đích test.
rule_path: ../../../../rules/.../rule.yml        # tùy chọn - override auto-discovery bằng id
tests:
  - name: Fires on a single webshell-style discovery event
    data: dataset_01_webshell_discovery.json     # đường dẫn tới 1 dataset (list các event JSON)
    pass_condition: 'count > 0'                   # count = số event trong dataset mà rule khớp
    description: giải thích ngắn (tùy chọn)

  - name: Fires exactly once on a realistic mixed batch
    data: dataset_02_mixed_batch.json
    pass_condition: 'count == 1'

  - name: Does not fire on benign administrative usage
    data: dataset_03_benign_admin_activity.json
    pass_condition: 'count == 0'
```

Example:

- Rule location `rules/windows/process_creation/proc_creation_win_mimikatz_command_line.yml`

- Example test location:

```
tests/unit/windows/process_creation/bd5b7103-d118-4331-b5b2-12a8b8861741.test.yml
tests/fixtures/windows/process_creation/bd5b7103-d118-4331-b5b2-12a8b8861741/event_01.json
```

# 4. Rule Schema & Metadata

## 4.1. Rule Schema

- A rule file is a single YAML document, one rule per file

```yaml
title:            
id:
related:
status:
description:      
references:       
author:           
date:             
modified:         
tags:             
logsource:        
  category:
  product:
  service:
  definition:
detection:        
  <search-identifier>:
  condition:
fields:           
falsepositives:   
level:            
custom:
  version:
  tenant:
  type: 
  tunning: 
```

## 4.2. Required and Optional Fields

| **Fields** | **Required** | **Type** | **Notes** |
| --- | --- | --- | --- |
| `title` | required | string, \<= 256 chars | A short, descriptive name of what the rule detects. |
| `id` | required | string, UUIDv4 | A globally unique identifier (UUID) for tracking the rule. |
| `related` | optinal | list of string | To be able to keep track of the relationships between detections |
| `status` | required | enum | `experimental` \| `test` \| `stable` \| `deprecated` \| `unsupported` |
| `type` | required | enum | `ttp` \| `anomaly` \| `hunting` |
| `description` | required | string | 1–3 sentences: behavior detected + why it matters. |
| `references` | optional | list of strings (urls) | At least 1 reference; internal-only rules may cite an internal runbook URL. |
| `author` | required | string | The creator or contributor of the rule |
| `date` | required | date, `YYYY-MM-DD` | Timestamps tracking creation and recent updates. |
| `modified` | optional | date, `YYYY-MM-DD` | Timestamps tracking creation and recent updates. |
| `tags` | optional | list of stringATT&CK (`attack.tXXXX`, `attack.<tactic>`);CVE (`cve.YYYY-NNNNN`);… | used to categorize or map Sigma rules into a variety of different security frameworks and availability standards. |
| `logsource` | required | mapping | Defines the target environment, structured via sub-fields: `category`, `product`, and `service` |
| `detection` | required | mapping | What malicious behaviour the rule searching for |
| `fields` | optional | list of strings | Fields recommended for triage/context display. |
| `falsepositives` | optional | list of string | Known scenarios or legitimate administrative activities that might trigger the rule. |
| `level` | required | enum | The relative severity or priority (e.g., `informational`, `low`, `medium`, `high`, `critical`). |
| `custom.version` | required | string | `1.0` \| `1.1` \| …. |
| `custom.type` | required | enum | `ttp` \| `anomaly` \| `hunting` |
| `custom.tenant` | optinal | string |  |
| `custom.tunning` | optinal | boolean | `true`, `false` |

## 4.3. Detection Logic Conventions

- `logsource`: always specify the narrowest applicable combination of `category`/`product`/`service`. Prefer `category` (e.g., `process_creation`) over a bare `product`, since categories map more predictably across backends' pipelines.
- `detection`
    - Search-identifiers are named semantically (`selection`, `filter_main_<reason>`, `filter_optional_<reason>` - following the SigmaHQ filter-naming convention referenced in the wiki), never `selection1`/`selection2`. (link: <https://sigmahq.io/docs/basics/rules.html#detection> )
    - Every `filter_optional_*` (suppressing known-noisy-but-not-universal behavior) must have a corresponding `falsepositives` entry explaining what it suppresses.
- `condition`: kept as simple boolean logic over identifiers (`selection and not filter_main_x`); complex nested boolean logic is a signal the rule should be split into two rules
- **Fields needing additional project metadata beyond what Sigma provides**:
    - `tags`(ATT&CK portion) → depends on the project's pinned ATT&CK Enterprise matrix version, so technique validity is a moving target the rule schema alone can't capture.
    - `logsource`: depends on `config/pipelines/*.yml` (which field-mapping exists)


## 4.4 Rule version

`custom.version` là version gắn với rule cụ thể, phản ánh nội dung rule đã thay đổi bao nhiêu lần và ở mức độ nào. Độc lập với package version và status.

```
custom:
  version: "1.2"    # MAJOR.MINOR
  ...
```

Format: `MAJOR.MINOR`. Quy tắc:

| **Bump** | **Điều kiện** | **Field ảnh hưởng** |
| --- | --- | --- |
| **MAJOR** (`X.y` → `(X+1).0`) | Thay đổi logic phát hiện | Khối `detection:` (bất kỳ search-identifier nào, hoặc `condition`) |
| **MINOR** (`x.Y` → `x.(Y+1)`) | Thay đổi metadata/tunning | `description`, `title`, `tags`, `level`, `falsepositives`, `references`, `fields`, thêm/sửa `filter_optional_*` bên trong `detection:` mà không đổi `condition` gốc,….. |
| Không bump | File không đổi nội dung có ý nghĩa (chỉ đổi whitespace, comment, format lại YAML) | - |


## 4.5. Rule Example

```yaml
title: Suspicious LSASS Access From Uncommon Process
id: 8f0e5f2a-9e3b-4b7a-9c9d-2a6f0a7e1c4d
related:
  - id: 3b1f7a5e-1c9d-4a2b-8e6f-5d4c3b2a1f0e
    type: derived
status: test
description: Detects process access to lsass.exe (a common credential-dumping target, ATT&CK T1003.001) from a process image that is not on the project's known allow-list of debuggers, EDR agents, or backup tools.
references:
  - https://attack.mitre.org/techniques/T1003/001/
author: tina
date: 2026-06-02
modified: 2026-08-10
tags:
  - attack.credential-access
  - attack.t1003.001
logsource:
  category: process_access
  product: windows
detection:
  selection:
    TargetImage|endswith: '\lsass.exe'
  filter_main_known_tools:
    SourceImage|endswith:
      - '\MsMpEng.exe'
      - '\ProcessHacker.exe'
  filter_optional_backup_agent:
    SourceImage|endswith: '\veeam_agent.exe'
  condition: selection and not 1 of filter_main_* and not 1 of filter_optional_*
fields:
  - SourceImage
  - TargetImage
  - GrantedAccess
falsepositives:
  - Approved EDR/AV engines not yet in filter_main_known_tools (update allow-list)
  - Backup agents performing volume shadow copy operations (see filter_optional_backup_agent)
level: high
custom:
  version: 1.2
  tenant: abc
  type: ttp
  tunning: false
```


# Reference

- <https://sigmahq.io/> 
- <https://github.com/SigmaHQ/sigma-specification/blob/main/specification/sigma-rules-specification.md#yaml-file> 
- <https://github.com/SigmaHQ> 
- [https://github.com/splunk/security\_content](https://github.com/splunk/security_content) 
- <https://github.com/Azure/Azure-Sentinel>
