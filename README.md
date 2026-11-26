# Wazuh SIEM Home Lab: Endpoint Telemetry, MITRE ATT&CK Triage & CIS Compliance

A hands-on Security Operations Center (SOC) home lab built on Oracle VirtualBox to simulate real-world endpoint attacks, ingest Windows Security Event Logs via Wazuh Agent, triage alerts using MITRE ATT&CK mappings, and audit system hardening against CIS Benchmarks.

---

## 1. Lab Architecture & Environment

| Component | Role | Hostname / Agent ID | Network IP |
| :--- | :--- | :--- | :--- |
| **Wazuh SIEM Server** (Ubuntu Linux) | Manager, Indexer & Dashboard | `wazuh-server` | `192.168.56.102` |
| **Monitored Endpoint** (Windows 11) | Wazuh Agent (`windows_eventchannel`) | `Windows11-Host` (`001`) | `192.168.56.1` |

* **Network Isolation:** Configured VirtualBox Host-Only Adapter (`192.168.56.0/24`) for dedicated agent-to-manager telemetry alongside NAT for package updates.
* **Agent Enrollment:** Registered `Windows11-Host` via `agent-auth.exe` and verified active real-time log ingestion from the Windows Security Event Channel.

![Wazuh Threat Hunting Dashboard Overview](Screenshot%20(288).png)

---

## 2. Simulated Attack Scenarios & Tier 1 Alert Triage

### Scenario A: Credential Brute-Force / Enumeration (`MITRE T1110`)
* **Simulation:** Generated failed network authentication attempts against a non-existent user (`fake_attacker`) to simulate credential stuffing/enumeration.
* **SIEM Detection:** Triggered Wazuh **Rule `60122`** (*Logon Failure - Unknown user or bad password*, Level 5) mapped to **Windows Event ID `4625`** (`AUDIT_FAILURE`).
* **Forensic Indicators Triaged:**
  * `data.win.eventdata.targetUserName`: `fake_attacker`
  * `data.win.eventdata.logonType`: `3` (Network logon via `NtLmSsp`)
  * `data.win.eventdata.status` / `subStatus`: `0xc000006d` / `0xc0000064` (User name does not exist)
  * `data.win.eventdata.ipAddress` / `ipPort`: `127.0.0.1` / `55327`

![Brute Force Alert and CIS Compliance Log](Screenshot%20(290).png)
![Event ID 4625 Document Details](Screenshot%20(292).jpg)

---

### Scenario B: Local Account Persistence Lifecycle (`MITRE T1136.001` / `T1098`)
* **Simulation:** Executed PowerShell administrative commands (`net user soc_test_user /add` followed by `/delete`) to simulate unauthorized local account creation and cleanup.
* **SIEM Detection:** Captured the full account lifecycle across multiple correlated rules:
  * **Rule `60109`** (Level 8): *User account enabled or created* (**Event IDs `4720`, `4722`**)
  * **Rule `60170`** (Level 5): *Users Group Changed* (**Event ID `4732`**)
  * **Rule `60111`** (Level 8): *User account disabled or deleted* (**Event ID `4726`**)
* **Forensic & Compliance Indicators Triaged:**
  * `decoder.name`: `windows_eventchannel`
  * `data.win.eventdata.targetUserName`: `soc_test_user`
  * `data.win.eventdata.subjectUserName`: Administrative session executing the command
  * **Mapped Compliance Frameworks:** NIST 800-53 (`AC.2`, `IA.4`, `AU.14`, `AC.7`), PCI-DSS (`8.1.2`, `10.2.5`), HIPAA (`164.312.a.2.I`), GDPR (`IV_35.7.d`), and SOC 2 (`CC6.8`, `CC7.2`, `CC7.3`).

![Account Persistence Lifecycle Events](Screenshot%20(298).jpg)
![Event ID 4722 Full Forensic Table](Screenshot%20(301).png)
![Decoder and Compliance Framework Mapping](Screenshot%20(302).jpg)

---

## 3. Security Configuration Assessment (SCA)
* **CIS Benchmark Auditing:** Leveraged Wazuh SCA module (`Rule 19005`) to continuously evaluate `Windows11-Host` against the **CIS Microsoft Windows 11 Enterprise Benchmark v3.0.0**, identifying configuration drift and hardening gaps.

---

## Key Skills Demonstrated
* SIEM Deployment & Administration (Wazuh Manager, Indexer, Dashboard)
* Windows Security Event Log Analysis (`Event IDs 4625, 4720, 4722, 4732, 4726`)
* MITRE ATT&CK Framework Mapping (`T1110`, `T1136.001`, `T1098`)
* Tier 1 SOC Alert Triage, Indicator Extraction & Compliance Auditing (CIS, NIST 800-53, PCI-DSS)
