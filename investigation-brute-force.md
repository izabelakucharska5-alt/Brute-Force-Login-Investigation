# Brute Force Login Investigation — SOC L1

**Project status:** In progress  
**Dataset:** [`data/brute_force_auth_logs.csv`](data/brute_force_auth_logs.csv)  
**Environment:** Splunk  
**Index:** `main`


## 1. Authentication Event Overview

**Objective:** Get an overview of authentication events and determine the distribution of successful and failed login attempts.

**Executed SPL:**

```spl
index=main source="brute_force_auth_logs.csv"
| stats count by result
| sort - count
```

**Evidence:**

![Authentication Event Overview — Splunk results](Screenshots/01-authentication-overview.png)

**Results:**

The search returned 14 authentication events:

| Authentication result | Event count |
|---|---:|
| Failure | 9 |
| Success | 5 |
| **Total** | **14** |

**Analysis:**

Failed authentication attempts account for approximately 64.3% of all recorded events, while successful logins account for 35.7%.

The number of failed attempts indicates that authentication activity requires further investigation. However, this overview alone is insufficient to classify the activity as a brute-force attack.

The next step is to identify which accounts and source IP addresses are associated with the failed login attempts.


## 2. Failed Login Analysis

**Objective:** Identify accounts targeted by repeated failed authentication attempts and examine the associated source IP addresses, locations and devices.

**Executed SPL:**

```spl
index=main source="brute_force_auth_logs.csv" result="failure"
| stats count as failed_attempts values(src_location) as locations values(device_id) as devices by user src_ip
| sort - failed_attempts
```

![Failed Login Summary — Splunk search and results](Screenshots/02-failed-login-summary.png)

**Results:**

The search returned 9 failed authentication events grouped into two user/IP combinations.

| User | Source IP | Failed attempts | Location | Device |
|---|---|---:|---|---|
| alice.johnson | `203.0.113.25` | 8 | Frankfurt, Germany | unknown |
| bob.smith | `198.51.100.11` | 1 | Warsaw, Poland | BOB-LAPTOP-01 |

**Analysis:**

Eight failed login attempts were associated with `alice.johnson`, all originating from the same source IP address and an unknown device, with Frankfurt, Germany recorded as the location.

In comparison, `bob.smith` had only one failed login attempt from a known device in Warsaw.

The repeated failures targeting Alice's account represent a suspicious authentication pattern consistent with a possible brute-force attempt.

**Preliminary assessment:** Alice's account requires further investigation. The next step is to examine her complete authentication history and determine whether any successful login occurred after the repeated failures.

**Note:** The dataset is synthetic. The IP addresses and geographic locations are simulated indicators and should not be treated as real-world threat intelligence.



## 3. Alice Johnson — Authentication Timeline

**Objective:** Review the complete authentication history of the targeted account and determine whether repeated failed login attempts were followed by a successful authentication.

**Executed SPL:**

```spl
index=main source="brute_force_auth_logs.csv" user="alice.johnson"
| table _time user src_ip src_location device_id action result details
| sort 0 _time
```

![Alice Authentication Timeline — Splunk search and results](Screenshots/03-alice-authentication-timeline.png)

**Results:**

The search returned 10 authentication events associated with Alice Johnson.

The observed sequence was:

| Time | Source IP | Location | Device | Result |
|---|---|---|---|---|
| 08:30:00 | `198.51.100.10` | Warsaw, Poland | ALICE-LAPTOP-01 | Success |
| 09:02:01–09:04:36 | `203.0.113.25` | Frankfurt, Germany | unknown | 8 × Failure |
| 09:05:12 | `203.0.113.25` | Frankfurt, Germany | unknown | Success |

All eight failed attempts reported `Invalid password`.

The final successful authentication was recorded with the detail:

`Successful sign-in after repeated failed attempts from same source IP`

**Analysis:**

The timeline reveals a suspicious sequence of authentication events:

- Alice initially authenticated successfully from her known device in Warsaw.
- Eight consecutive failed login attempts followed from a different IP address in Frankfurt.
- All failed attempts originated from the same IP address and an unknown device.
- A successful authentication occurred from that same suspicious source IP just 36 seconds after the last failed attempt.

The change from Warsaw to Frankfurt within 32 minutes also represents a potential impossible-travel indicator.

**Assessment:** The observed pattern is consistent with a brute-force attempt followed by a potentially successful account compromise. The successful authentication after repeated failures significantly increases the severity of the incident.

**Note:** The dataset uses synthetic IP addresses and simulated geographic locations. The impossible-travel observation is therefore a scenario indicator, not real-world geolocation evidence.
