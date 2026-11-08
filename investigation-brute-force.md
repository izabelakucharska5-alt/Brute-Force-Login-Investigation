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

