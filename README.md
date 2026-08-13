# Cyber-Defense-Incident-Response-Azure-Sentinel-KQL-Threat-Hunting
Conducted a multi-stage forensic investigation and threat hunting exercise analyzing an automated data extortion campaign targeting an internet-exposed MySQL server and co-located Windows RDP surface. Integrated forensic triage packages, Defender Advanced Hunting telemetry, and custom KQL workbooks to map attack progression and geographic scope.

## 🗺️ Geo-Mapping & Threat Visualization

*   **Purpose:** To visualize, on a single map, every external source that reached the affected environment — both the Windows VM's RDP surface and the MySQL server — so the geographic spread and success/failure mix of the attack can be assessed at a glance, per the assignment brief (*"show where all the attacks came from against your VM and/or MySQL Server"*).
*   **Method:** An Azure Monitor Workbook was built combining two data sources into one KQL union:
    *   **RDP / Windows VM:** Live query against `DeviceLogonEvents`, filtered to devices named `corp-by01*`, network/remote-interactive logons from public IPs only, over the last 3 days.
    *   **MySQL Server (3306):** The confirmed attacker IPs already extracted in `REP-20260808-002 §4` (MySQL audit log isn't a native Sentinel table in this environment, so these are plotted as a fixed list pending onboarding of a live MySQL audit source).
    *   **RPC / Other:** The anomalous port-135 finding from the DFIR comparison report.
    *   Each source IP was geolocated with `geo_info_from_ip_address()` and plotted as one bubble, sized by attempt count and colored by number of successes (green → red).

### 📊 Summary Statistics

| Metric | Count / Detail |
| :--- | :--- |
| **Distinct External Source IPs** | 24 distinct IPs touched the environment across all three surfaces. |
| **Origin Countries** | 14 distinct countries were the origin of at least one connection. |
| **Total Attempts** | 275 total attempts recorded across all surfaces; 26 successful authentications. |
| **RDP Surface** | 264 attempts, 16 successes, 248 failures. |
| **MySQL Surface** | 10 attempts, 10 successes, 0 failures — every observed MySQL connection succeeded. |
| **RPC Surface** | 1 connection, 0 successes (reconnaissance-style probe, not an authentication event). |

---

> **KQL — Underlying Workbook Query / Data Aggregation:**
> ```kql
> // Combined Threat Geo-Mapping Query
> union 
> (
>     DeviceLogonEvents
>     | where DeviceName has "corp-by01"
>     | where Timestamp > ago(3d)
>     | where RemoteIPType == "Public"
>     | where LogonType in ("RemoteInteractive", "Network")
>     | extend AttackSurface = "RDP / Windows VM"
>     | extend Success = iff(ActionType == "LogonSuccess", 1, 0)
>     | project Timestamp, RemoteIP, AttackSurface, Success
> ),
> (
>     // Placeholder union for MySQL historical IOC list mapping
>     datatable(Timestamp:datetime, RemoteIP:string, AttackSurface:string, Success:int)
>     [
>         datetime(2026-08-06), "194.88.98.112", "MySQL Server (3306)", 1
>     ]
> )
> | evaluate ipv4_lookup(IpToGeoInfo, RemoteIP, IP_Address)
> | summarize AttemptCount=count(), SuccessCount=sum(Success) by RemoteIP, Country, AttackSurface, lattitude, longtitude
> | order by AttemptCount desc
> ```

[![Hızlı Resim](https://i.hizliresim.com/ye0k0j9f.png)](https://hizliresim.com/ye0k0j9f)

# 🔎 DFIR Comparison Report — Suspected MySQL Extortion / Data-Access Incident on `by_corp_01`

**Host:** CORP-BY01-YB241 (Azure VM, 10.3.0.15)  
**Report ID:** REP-20260808-001  
**Analyst:** Berkay Yildirim  
**Date written:** 2026-08-08  

## 1. Executive Summary
An internet-facing Azure VM running MySQL Server 8.0 was investigated after a suspected extortion/ransom event referencing a Bitcoin payment address, an onionmail contact, and a "DATAID" reference code (IOCs supplied by the intake ticket).

Forensic triage was collected twice — once on 2026-08-05 (pre-incident baseline) and once on 2026-08-07 (post-incident) via Microsoft Defender's live-response collection. The data confirms the host exposed MySQL (3306/33060) and RDP (3389) to all interfaces both before and after the incident window, and shows a new, previously-absent external connection to the host's RPC endpoint mapper (port 135) from IP 194.88.98.112 that appears only in the post-incident snapshot.

No ransom note, SQL command history, or the specific IOCs supplied in the ticket were found anywhere in the collected triage data — the two collection bundles contain OS-level live-response artifacts (processes, netstat, prefetch, autoruns, event-log export) but no MySQL audit logs and no Defender Advanced Hunting exports, so the actual database compromise (DROP/RENAME/exfil, ransom-table insertion) is not directly evidenced here. This report documents what the available data supports and lists the specific hunts needed to close the gaps.

## 2. Incident Details

| Field | Value |
| :--- | :--- |
| **Detection date/time** | Not determined from available logs — no alert/ticket timestamp included in either package. Post-breach collection was triggered 2026-08-07T05:52:43Z. |
| **Reporter** | Not determined from available logs |
| **Classification** | Suspected data-extortion / unauthorized database access (MySQL), pending confirmation of exfiltration or destructive action against the database |
| **Severity** | High (pending scope confirmation) — internet-exposed DB server with local-admin RDP account and a new unexplained inbound RPC connection |
| **Affected system** | CORP-BY01-YB241 — Windows 11 Pro (build 26200), standalone/WORKGROUP Azure VM, IP 10.3.0.15, hosting MySQL Server 8.0 + MySQL Workbench |
| **Affected accounts** | bekowork (local Administrator, active RDP session in both collections); administrator |
| **Collection packages** | Pre-MDE: GUID 16a0124f-763c-4787-ab75-e355f6fde1bb, collected 2026-08-05T21:33:35Z. <br><br>Post-breach: GUID 6b162504-837a-49d5-a742-c89a577bd844, collected 2026-08-07T05:52:43Z. |

> **KQL — Confirm detection trigger/alert:**
> ```kql
>// Confirm asset inventory & any prior alerts tied to the host
>DeviceInfo
>| where DeviceName in ("corp-by01-yb241", "corp-by01-yb241da")
>| project TimeGenerated, DeviceName, PublicIP, OSPlatform
>AlertInfo
>| where Timestamp between (datetime(2026-08-05) .. datetime(2026-08-08))
>| where DeviceName has "corp-by01"
> ```
[![Hızlı Resim](https://i.hizliresim.com/bsznhnat.png)](https://hizliresim.com/bsznhnat)
 ## 3. Impact Assessment

*   **Confidentiality:** Potential exposure of MySQL database contents — MySQL service was listening on `0.0.0.0:3306` and `0.0.0.0:33060` (all interfaces) in both the pre- and post-incident snapshots, meaning the port was open to the network prior to this incident, not opened as part of it. Actual data accessed/exfiltrated: not determined from available logs (no query audit log in this package).
*   **Integrity:** Not determined — no evidence of `DROP`/`RENAME`/`TRUNCATE` was found because no MySQL query log was supplied. A ransom-note table (common in this style of MySQL extortion) could not be confirmed or ruled out from OS-level artifacts alone.
*   **Availability:** `mysqld.exe` was running and the service was reachable in the post-breach snapshot; no evidence of service outage in either collection.
*   **Scope:** Single host confirmed (`CORP-BY01-YB241`). Whether other hosts/databases were affected: not determined from available logs.
*   **Business impact:** Not determined from available logs (no asset criticality/data classification provided).

> **KQL — Assess blast radius / other exposed DB hosts:**
> ```kql
> DeviceNetworkEvents
> | where LocalPort in (3306, 33060) and LocalIPType == "Public"
> | where RemoteIP != "10.3.0.15"
> | summarize ConnectionCount=count() by DeviceName, RemoteIP, LocalPort
> | order by ConnectionCount desc
> ```

---

## 4. Indicators of Compromise (IOCs)

| Type | Value | Source | Notes |
| :--- | :--- | :--- | :--- |
| **BTC address** | `bc1qk9kvwhzt60u3eqcjllqlj44h0tj7w7n72apz99` | Provided (ticket/intake) | Not found in collected triage data |
| **Contact email** | `ak+28t2@onionmail.org` | Provided (ticket/intake) | Not found in collected triage data |
| **Reference URL** | `hxxps://2no[.]co/2mysql` | Provided (ticket/intake) | Not found in collected triage data |
| **DATAID** | `28T2` | Provided (ticket/intake) | Not found in collected triage data |
| **Suspicious external IP** | `194.88.98.112:31384` → local port 135 (RPC endpoint mapper), ESTABLISHED | `ActiveNetConnections.txt` (post-breach only) | Owning process: `svchost.exe` / RpcEptMapper (PID 740). New connection not present 2026-08-05 |
| **Exposed service** | `0.0.0.0:3306`, `0.0.0.0:33060` LISTENING | `ActiveNetConnections.txt` (pre- and post-breach) | MySQL Server 8.0 (`mysqld.exe`), internet-reachable in both snapshots |
| **Exposed service** | `0.0.0.0:3389` LISTENING | `ActiveNetConnections.txt` (pre- and post-breach) | RDP; only established sessions observed are from internal Azure VNet address `10.0.8.4` |
| **Local admin account** | `bekowork` | `LocalGroups.txt` | Member of local Administrators; active RDP session in both collections |

> **Note:** No IOCs from the intake ticket (BTC address, onionmail contact, reference URL, DATAID) were recoverable from the supplied Windows OS triage artifacts. These were most likely surfaced from the ransom/extortion table left inside the MySQL database itself or from a direct communication to the victim, neither of which is captured by this collection.

> **KQL — Pivot on the known IOCs across the estate:**
> ```kql
> // Pivot on discovered attacker infrastructure across the estate
>let iocIPs = dynamic(["77.90.185.21","64.89.163.169","77.90.185.30","213.209.159.115"]);
>DeviceNetworkEvents
>| where RemoteIP in (iocIPs)
>| project TimeGenerated, DeviceName, ActionType, LocalIP, LocalPort, RemoteIP, RemotePort
> ```
[![Hızlı Resim](https://i.hizliresim.com/xngg5nkn.png)](https://hizliresim.com/xngg5nkn)
## 5. Timeline

| Time (UTC) | Event | Source |
| :--- | :--- | :--- |
| **2026-08-04 15:12** | OS image install date for the VM | `SystemInformation.txt` (both packages) |
| **2026-08-05 14:48** | Host boot (pre-incident collection cycle) | `SystemInformation.txt` (pre-MDE) |
| **2026-08-05 14:48** | `mysqld.exe` service start (PID `3920` → `5096`) | `Processes.csv` (pre-MDE) |
| **2026-08-05 14:53** | `bekowork` interactive RDP logon | `QueryUser.txt` (pre-MDE) |
| **2026-08-05 21:33** | Pre-incident forensic baseline collected (package `16a0124f...`) — MySQL already listening on `0.0.0.0:3306/33060`; no port 135 connection | `ActiveNetConnections.txt`, `Forensics Collection Summary.csv` (pre-MDE) |
| **2026-08-06 17:24** | Host reboot | `SystemInformation.txt` (post-breach) |
| **2026-08-06 17:25** | `mysqld.exe` restarted (PID `4084` → `4956`) | `Processes.csv` (post-breach) |
| **2026-08-06 17:26** | `bekowork` interactive RDP logon | `QueryUser.txt` (post-breach) |
| **Undetermined** | Initial access / database compromise | **Gap** — no MySQL auth/query log supplied |
| **Undetermined** | Ransom note / extortion artifact placement inside the database | **Gap** — no MySQL query log available to confirm |
| **2026-08-07 05:52** | New/anomalous inbound TCP session `194.88.98.112:31384` → `10.3.0.15:135` (RpcEptMapper), ESTABLISHED | `ActiveNetConnections.txt` (post-breach) |
| **2026-08-07 05:52–05:53** | Post-breach forensic collection performed (package `6b162504...`) | `Forensics Collection Summary.csv` (post-breach) |

> **KQL — Reconstruct initial access via MDE:**
> ```kql
> // Build a consolidated cross-source timeline for the incident window union
>(DeviceLogonEvents | where TimeGenerated between (datetime(2026-08-05) .. datetime(2026-08-08))),
>(DeviceProcessEvents | where TimeGenerated between (datetime(2026-08-05) .. datetime(2026-08-08))),
>(DeviceNetworkEvents | where TimeGenerated between (datetime(2026-08-05) .. datetime(2026-08-08)) and RemotePort == 3306)
| sort by TimeGenerated asc
> ```

> **KQL — MySQL auth/query pivot:** *(requires the MySQL audit tables referenced in the brief, not present in this package)*
> ```kql
> MySQLAudit_CL_Auth
> | where TimeGenerated between (datetime(2026-08-04) .. datetime(2026-08-07T06:00:00Z))
> | where Host_s == "10.3.0.15" or Host_s == "CORP-BY01-YB241"
> | project TimeGenerated, User_s, SourceIP_s, ConnectionStatus_s
> 
> MySQLAuth_CL_Query
> | where TimeGenerated between (datetime(2026-08-04) .. datetime(2026-08-07T06:00:00Z))
> | where Command_s has_any ("DROP","RENAME","SELECT INTO OUTFILE","CREATE TABLE")
> | project TimeGenerated, User_s, SourceIP_s, Command_s
> | order by TimeGenerated asc
> ```
[![Hızlı Resim](https://i.hizliresim.com/zpcoarvu.png)](https://hizliresim.com/zpcoarvu)
---

## 6. Root Cause / Attack Vector

*   **Confirmed:** The MySQL service (`mysqld.exe`, MySQL Server 8.0) was bound to all interfaces (`0.0.0.0:3306`, `0.0.0.0:33060`) on an internet-facing Azure VM prior to the incident, per the pre-breach snapshot. This is a pre-existing exposure condition, not something the attacker created.
*   **Suggestive but not confirmed:** A new external IP (`194.88.98.112`) established a connection to the RPC endpoint mapper (port 135) that was not present in the pre-incident baseline. Port 135 is not the MySQL port, so this is either (a) unrelated scanning/reconnaissance activity, or (b) a secondary access attempt via SMB/RPC. It does not by itself explain a MySQL compromise.
*   **Not determined from available logs:**
    *   Whether the attacker authenticated to MySQL directly (credential stuffing, default root credentials, weak password) — no MySQL auth log in this package.
    *   Whether RDP (`3389`, also exposed to `0.0.0.0`) was the entry vector — the only RDP peer observed in either snapshot is the internal address `10.0.8.4`, which argues against external RDP brute force, but Windows Security event log content could not be reviewed (see Evidence/Gaps).
    *   Whether `bekowork`'s credentials were compromised versus this being legitimate DBA activity that happened to be active during both collection windows.
*   **Working hypothesis (unconfirmed):** Opportunistic scan-and-extort campaign against an exposed MySQL instance, consistent in style with mass MySQL-ransom campaigns (drop tables, leave a ransom table with contact/BTC/reference-code details). This matches the ticket's IOC set but is not independently corroborated by the OS artifacts reviewed.

> **KQL — Confirm exposure window and any credential-stuffing pattern:**
> ```kql
> // Confirm external exposure and any config/firewall change activity
> DeviceNetworkEvents
> | where DeviceName == "corp-by01-yb241" and LocalPort == 3306
> | where ActionType == "InboundConnectionAccepted"
> | summarize FirstSeen=min(TimeGenerated), LastSeen=max(TimeGenerated), Count=count() by RemoteIP
> | order by Count desc

[![Hızlı Resim](https://i.hizliresim.com/a4gaqp0u.png)](https://hizliresim.com/a4gaqp0u)

## 7. Response Actions

### Taken (Evidenced by the collections themselves)
*   Live-response forensic collection performed twice via Defender (baseline Aug 5, post-incident Aug 7), preserving process list, netstat, autoruns, scheduled tasks, prefetch, and a filtered Security event log export.

### Recommended / Not Yet Confirmed as Done

| Action | Priority |
| :--- | :--- |
| Firewall off `0.0.0.0:3306/33060` from the public internet; restrict to a VPN/bastion or specific admin CIDR | **Immediate** |
| Rotate all MySQL account credentials (especially root/admin) and review `mysql.user` for unauthorized accounts | **Immediate** |
| Rotate `bekowork` and administrator local Windows credentials; review for unauthorized admin accounts | **Immediate** |
| Block/investigate `194.88.98.112` at the network edge | **Immediate** |
| Restrict RDP (`3389`) to bastion/VPN only if not already enforced (currently only seen from internal `10.0.8.4`, but port is bound to `0.0.0.0`) | **High** |
| Pull and review MySQL general/audit query log for the incident window to determine actual data impact | **High** |
| Restore database from last known-good backup if integrity is confirmed compromised | **High** *(contingent on findings)* |
| Full-disk/registry forensic review (not just live triage) if compromise is confirmed | **Medium** |

> **KQL — Verify containment (no further external DB connections post-remediation):**
> ```kql
>// Verify remediation: confirm port 3306 no longer reachable from external IPs after change
>DeviceNetworkEvents
>| where DeviceName == "corp-by01-yb241" and LocalPort == 3306
>| where TimeGenerated > datetime(<remediation_timestamp>)
>| where RemoteIP !startswith "10." and RemoteIP !startswith "192.168."
> ```
[![Hızlı Resim](https://i.hizliresim.com/zkl43v7x.png)](https://hizliresim.com/zkl43v7x)
## 8. Evidence & Gaps

### Evidence Analyzed
| Artifact Package(s) | Used For |
| :--- | :--- |
| `Processes.csv` (pre + post) | Confirming `mysqld.exe` service instances, parent/child relationships, start times |
| `ActiveNetConnections.txt` (pre + post) | Listening ports, established sessions, tracking the new port-135 connection |
| `FirewallExecutionLog.txt` (pre + post) | Attempted collection of `pfirewall.log` — file not present on host (Windows Firewall logging not enabled) |
| `SMB Session\Summary.txt` (pre + post) | Confirmed no active SMB sessions at either collection time |
| `QueryUser.txt`, `LocalGroups.txt` (pre + post) | Active RDP session owner and local admin membership verification |
| `Autoruns.txt` (pre + post) | Diffed for persistence changes — only benign OS/GUID churn observed, no new autorun entries of note |
| `ScheduledTasks.csv` (post) | Non-Microsoft tasks limited to OneDrive updater tasks under `bekowork` |
| `PrefetchFilesList.txt` + `.pf` files (pre + post) | Execution history; only expected MySQL tooling and standard OS binaries observed — no attacker tooling identified |
| `Security.evtx` (pre + post) | Present but not reviewable in this pass — text export is empty; requires native `.evtx` parsing tooling |
| `MpCmdRunLog.txt` (pre + post) | Defender log-collection meta-log only; no threat detections listed |
| `Forensics Collection Summary.csv` (pre + post) | Collection timestamps and package GUIDs used to anchor the timeline |

### Identified Gaps
1. `MySQLAudit_CL_Auth.csv` and `MySQLAuth_CL_Query.csv` referenced in the intake were not present in either uploaded package — no DB-level auth or query evidence available.
2. `DeviceProcessEvents`, `DeviceLogonEvents`, `DeviceRegistryEvents`, `DeviceFileEvents`, `NTANetAnalytics` (MDE Advanced Hunting tables) were not exported/provided — only local live-response triage snapshots. The KQL queries above should be run against those tables directly in the Defender portal to fill these gaps.
3. `Security.evtx` could not be parsed in this review; a native Windows/Event Viewer or `python-evtx`/`Get-WinEvent` pass is required for logon (`4624`/`4625`/`4648`) and process-creation (`4688`) detail.
4. No ransom note, ransom table, or file matching the ticket's IOCs was found on the host — consistent with the compromise being purely inside the MySQL data layer rather than the filesystem, but not confirmed either way.

---
[![Hızlı Resim](https://i.hizliresim.com/skezgwma.png)](https://hizliresim.com/skezgwma)
## 9. Lessons Learned & Recommendations

*   **1. (Critical)** Remove MySQL from public exposure. The root enabling condition — `mysqld` bound to `0.0.0.0:3306/33060` on an internet-facing VM — predates this incident and should be the top remediation regardless of root-cause confirmation.
*   **2. (Critical)** Enable MySQL general/audit logging (or the referenced `MySQLAudit_CL_*` pipeline) before the next incident — without it, DB-level compromise cannot be forensically confirmed or scoped.
*   **3. (High)** Enforce MFA and IP allow-listing on RDP, and disable public binding on port `3389` even though observed sessions in this dataset were internal-only.
*   **4. (High)** Onboard the MDE Advanced Hunting tables (`DeviceNetworkEvents`, `DeviceProcessEvents`, `DeviceLogonEvents`) for this host into routine retention/query access — this investigation had to rely on point-in-time live-response snapshots instead of queryable telemetry.
*   **5. (Medium)** Enable Windows Firewall connection logging (`pfirewall.log`) — it was requested by the collection tooling but not present, removing a potentially useful data source.
*   **6. (Medium)** Review and rotate local admin account (`bekowork`) usage — a standing local-admin RDP account on a database host increases blast radius if credentials are ever compromised; consider least-privilege / just-in-time administrative models instead.
