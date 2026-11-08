# SOC-Brute-Force-Investigation

**Brute Force Login Investigation**

![Status](https://img.shields.io/badge/Status-In%20Progress-yellow) ![Project](https://img.shields.io/badge/Type-Blue%20Team-blue) ![SIEM](https://img.shields.io/badge/SIEM-Splunk-black)

A junior-level, simulated **SOC L1 investigation** focused on identifying and assessing repeated failed authentication attempts and a potentially suspicious successful sign-in.

## Project Scenario

A fictional employee account receives multiple failed sign-in attempts from the same external IP address. A successful sign-in is then recorded from that source. The investigation will use Splunk to review the authentication events, establish the sequence of activity, and assess whether the pattern is consistent with a brute-force attempt.

The goal is to demonstrate a practical SOC L1 workflow: examine the available evidence, identify suspicious activity, document findings, and recommend appropriate escalation or containment actions. The project is intentionally scoped to junior analyst-level tasks.

## Objectives

- Review authentication events in Splunk.
- Distinguish successful and failed sign-ins.
- Identify repeated failures associated with a user and source IP.
- Review the timeline of authentication attempts.
- Assess the risk of a successful sign-in following repeated failures.
- Document findings and recommend appropriate SOC L1 response actions.

## Dataset

The project uses a synthetic CSV dataset containing **14 sign-in events**.

File: [`data/brute_force_auth_logs.csv`](data/brute_force_auth_logs.csv)

The dataset includes the following fields:

| Field | Description |
|---|---|
| `timestamp` | Date and time of the authentication event, including timezone offset |
| `event_type` | Event category |
| `user` | Account associated with the event |
| `src_ip` | Source IP address |
| `src_location` | Approximate source location |
| `device_id` | Device identifier, where available |
| `result` | Authentication result (`success` or `failure`) |
| `auth_method` | Authentication method |
| `mfa` | MFA result or status |
| `risk` | Risk level recorded for the event |
| `details` | Additional event context |

## Tools & Technologies

- **Splunk** — SIEM platform used to search and investigate the CSV events.
- **SPL** — Splunk Search Processing Language used for filtering, sorting, and summarizing authentication activity.
- **CSV** — Structured source data for the simulated investigation.

## Repository Structure

```text
SOC-Brute-Force-Investigation/
├── README.md
├── investigation.md
├── data/
│   └── brute_force_auth_logs.csv
└── Screenshots/
    └── .gitkeep
```

## Investigation Documentation

The investigation is documented step by step in [`investigation.md`](investigation.md). Each search will be recorded when it is executed, together with its exact SPL command, the corresponding Splunk screenshot, the observed results, and the analyst's interpretation.

Screenshots will be stored in the [`Screenshots/`](Screenshots/) directory and linked directly below the relevant SPL search in the investigation report.

## Disclaimer

This is an educational project based entirely on fictional users and synthetic authentication events. The IP addresses used belong to documentation ranges reserved for examples and must not be treated as real-world indicators of malicious activity. No production accounts or systems are involved.
