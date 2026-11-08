# SOC-Brute-Force-Investigation

**Brute Force Detection & Authentication Incident Investigation**

![Status](https://img.shields.io/badge/Status-Completed-brightgreen) ![Project](https://img.shields.io/badge/Type-Blue%20Team-blue) ![SIEM](https://img.shields.io/badge/SIEM-Splunk-black) ![Level](https://img.shields.io/badge/Level-Junior-blue)

A simulated **SOC L1 investigation** of suspicious authentication activity targeting an employee account in a fictional organization.

The project demonstrates how Splunk and SPL can be used to identify repeated failed login attempts, investigate suspicious source IP addresses, analyze authentication timelines and assess potential account compromise.

## Investigation Summary

The investigation identified a series of suspicious authentication attempts targeting Alice Johnson's account.

Key findings:

- **14** authentication events analyzed.
- **9** failed authentication attempts.
- **5** successful authentication events.
- **8 consecutive failed login attempts** against Alice's account.
- **1 successful authentication** from the same suspicious source IP following the failed attempts.
- **1 targeted account** associated with the suspicious IP address.

The suspicious activity originated from `203.0.113.25`, geolocated to Frankfurt, Germany, and involved an unknown device.

After eight consecutive failed attempts, a successful sign-in was recorded from the same IP address at 09:05:12.

The successful authentication occurred just 36 seconds after the final failed attempt.

## Focus Areas

- Authentication log analysis.
- Identification of repeated failed login attempts.
- Brute-force attack detection.
- Source IP investigation.
- User authentication timeline reconstruction.
- Successful versus failed login analysis.
- Identification of suspicious devices and geographic locations.
- Potential account compromise assessment.
- Incident triage and response recommendations.

## Technologies & Frameworks

- **Splunk Enterprise** — SIEM platform used to ingest and investigate synthetic authentication logs.
- **SPL** — Splunk Search Processing Language used to filter, aggregate and analyze authentication events.
- **CSV** — Structured dataset containing simulated login events.
- **Blue Team / SOC L1** — Security monitoring and incident investigation workflow.

## Repository Contents

| File / Directory | Description |
|---|---|
| [`investigation-brute-force.md`](investigation-brute-force.md) | Full investigation report, executed SPL searches, findings, analysis and screenshots |
| [`data/`](data/) | Synthetic authentication log dataset |
| [`Screenshots/`](Screenshots/) | Screenshots documenting the Splunk investigation process |

## Investigation Workflow

1. Reviewed the overall distribution of successful and failed authentication events.
2. Identified accounts with repeated failed login attempts.
3. Examined Alice Johnson's authentication history and reconstructed the event timeline.
4. Investigated the suspicious source IP address to determine which accounts it targeted.
5. Compared successful authentication events to identify unusual login activity.
6. Assessed the potential account compromise and documented recommended incident response actions.

The full investigation includes the exact SPL searches, corresponding Splunk screenshots, observed results and analysis.

See [`investigation-brute-force.md`](investigation-brute-force.md).

## Key Findings

The investigation identified a suspicious authentication pattern involving Alice Johnson's account:

- A normal successful sign-in was recorded from Warsaw, Poland, using her known device at 08:30.
- Eight failed login attempts originated from `203.0.113.25` between 09:02:01 and 09:04:36.
- The attempts originated from Frankfurt, Germany, and used an unknown device.
- A successful authentication followed at 09:05:12 from the same suspicious IP address.
- No other user accounts were associated with this source IP in the supplied dataset.

The geographic difference between Warsaw and Frankfurt within approximately 32 minutes also represents a potential impossible-travel indicator in the simulated scenario.

**Conclusion:** The observed activity is consistent with a targeted brute-force attempt against a single account, followed by a potentially successful account compromise.

The available logs do not establish the identity of the actor or what actions were performed after authentication.

## Recommended Incident Response

The investigation recommends escalating the incident to SOC L2 / Incident Response, verifying the activity with the account owner, securing the potentially compromised account, reviewing MFA activity and monitoring for further suspicious authentication events.

## Disclaimer

This is an educational Blue Team project based on a fictional scenario and synthetic security logs.

**All SPL searches were executed in Splunk Enterprise** against the supplied synthetic dataset.

No production infrastructure, real employee accounts or real security incidents were involved.

All names, locations and events are fictional. The IP addresses belong to documentation ranges reserved for examples and must not be treated as real-world malicious indicators.
