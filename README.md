# T1110 – RDP Brute Force (Hydra) Detected by Wazuh

## Objective
Simulate a real-world external/insider attack against an exposed RDP service and verify that Wazuh correctly detects and classifies the attack using MITRE ATT&CK.

## Lab topology

| Role | OS | IP | Notes |
|---|---|---|---|
| Attacker | Kali Linux 2026.2 | `192.168.176.x` | nmap, hydra |
| Victim | Windows 10 | `192.168.176.135` | Agent name `windows10`, local user `Testuser` |
| SIEM | Wazuh 4.14.10 (OVA) | `192.168.176.134` | Manager + Indexer + Dashboard |

## MITRE ATT&CK mapping

| Tactic | Technique | ID |
|---|---|---|
| Credential Access | Brute Force | **T1110** |
| Lateral Movement / Initial Access | Remote Services: RDP | T1021.001 |
| Defense Evasion / Persistence | Valid Accounts | T1078 |

---

## 1. Deploy Wazuh from the OVA

Downloaded the official virtual appliance and imported it into VirtualBox.

- Image: `wazuh-4.14.10.ova`
- Requirements: 64-bit host, hardware virtualization enabled, VirtualBox (or other OVA-compatible hypervisor)
- After boot, the dashboard is reachable at `https://<manager-ip>`

```bash
# Reference: https://documentation.wazuh.com/current/deployment-options/virtual-machine/
```

<img width="1917" height="957" alt="Screenshot 2026-11-15 201859" src="https://github.com/user-attachments/assets/d2aba19c-f744-4310-b323-87e73a833c6b" />


## 2. Deploy the Windows agent

From **Agents → Deploy new agent** in the dashboard, generated and ran the install command on the Windows 10 victim:

```powershell
Invoke-WebRequest -Uri https://packages.wazuh.com/4.x/windows/wazuh-agent-4.14.10-1.msi `
  -OutFile $env:tmp\wazuh-agent.msi

msiexec.exe /i $env:tmp\wazuh-agent.msi /q `
  WAZUH_MANAGER='192.168.176.134' `
  WAZUH_AGENT_NAME='windows10'

Get-Service WazuhSvc
Start-Service WazuhSvc
```

Confirmed the agent came up as **Active** on the manager's Agents list.

<img width="1655" height="947" alt="Screenshot 2026-11-15 204501" src="https://github.com/user-attachments/assets/bea28848-f23b-466d-bb44-532b87fd176a" />

<img width="1662" height="742" alt="Screenshot 2026-11-15 210623" src="https://github.com/user-attachments/assets/51d23eff-a5a5-4135-a562-a7e66f1ccee3" />

<img width="1663" height="872" alt="Screenshot 2026-11-15 211903" src="https://github.com/user-attachments/assets/baecf43b-7f19-4edb-a4ec-473c4a8fe74a" />

<img width="1472" height="645" alt="Screenshot 2026-11-15 212546" src="https://github.com/user-attachments/assets/85b89fc1-c87c-4c9b-b2af-05138fb9133c" />



## 3. Create a test account

```powershell
net user Testuser "Password123" /add
```

> ⚠️ `Testuser` was **not** added to the *Remote Desktop Users* group on purpose, to show a realistic failed-brute-force scenario later (see Results).

<img width="853" height="536" alt="Screenshot 2026-11-15 213218" src="https://github.com/user-attachments/assets/2abe4afa-bef5-4c4a-be4f-e533f4b9f7e3" />


## 4. Enable RDP and verify audit policy

Enabled Remote Desktop (System Properties → Remote Settings), then confirmed that logon auditing was active — **this is required** for Windows to generate the 4624/4625 events Wazuh relies on:

```powershell
auditpol /get /subcategory:"Logon"
# Logon   Success and Failure
```

<img width="1017" height="728" alt="Screenshot 2026-11-15 220923" src="https://github.com/user-attachments/assets/4513f216-8fab-4756-aa14-b692ed65b7c2" />


## 5. Recon from Kali

```bash
ping 192.168.176.135
nmap -p 3389 192.168.176.135
```

```
PORT     STATE SERVICE
3389/tcp open  ms-wbt-server
```

<img width="761" height="377" alt="Screenshot 2026-11-15 222454" src="https://github.com/user-attachments/assets/795ce6bf-c19b-4fff-828c-e05c18450345" />


## 6. Brute force with Hydra

Built a small custom password list:

```bash
cat password.txt
# Password1
# Summer2026
# Welcome123
# Test123
# Admin123
# Cyber123
# Winter2026
# Qwerty123
# Company123
# Password2026
```

Ran Hydra against the RDP service:

```bash
hydra -t 1 -V -l Testuser -P password.txt rdp://192.168.176.135
```

**Result:** 10/10 passwords attempted, 0 valid found — Hydra reported *"account not active for remote desktop"* for every attempt, because `Testuser` was never added to the Remote Desktop Users group, and the real password wasn't in the list. This is a realistic negative result and still generates a full set of failed-logon telemetry on the Windows side.

<img width="801" height="286" alt="Screenshot 2026-11-15 222531" src="https://github.com/user-attachments/assets/cea69f27-6eed-457b-8e74-6e50215b9e2c" />

<img width="1653" height="518" alt="Screenshot 2026-11-15 223037" src="https://github.com/user-attachments/assets/ead87f94-9682-494d-85db-e50e8de9e08c" />


## 7. Detection in Wazuh

### Dashboard / Threat Hunting overview
Alerts spiked immediately. The **Top 10 MITRE ATT&CKs** donut chart shows Remote Desktop Protocol, Valid Accounts and Domain Accounts among the top techniques during the attack window.

<img width="1920" height="1080" alt="Screenshot_2026-11-15_15_14_37" src="https://github.com/user-attachments/assets/e382aadb-a14a-4008-9992-9c8504830277" />

<img width="1920" height="1080" alt="Screenshot_2026-11-15_15_15_07" src="https://github.com/user-attachments/assets/883e614d-4d7d-4df1-95bd-9abbbd84c947" />


### Raw events — Event ID 4625
Filtering on Windows Event ID `4625` isolates the individual failed-logon attempts generated by Hydra:

```
rule.description: Logon Failure - Unknown user or bad password
rule.id: 60122
rule.level: 5
```

<img width="1920" height="1080" alt="Screenshot_2026-11-15_15_20_32" src="https://github.com/user-attachments/assets/abb81db9-cf2b-4b8b-8352-21db8e2c34fe" />


### MITRE ATT&CK classification
Wazuh's built-in MITRE module auto-tagged the alert:

```
rule.mitre.id:        T1110
rule.mitre.tactic:    Credential Access
rule.mitre.technique: Brute Force
```

<img width="865" height="130" alt="Screenshot 2026-11-15 234533" src="https://github.com/user-attachments/assets/7ae3d5f3-4cf2-4044-a5ed-98566f77de9e" />


---

## Results summary

| Check | Outcome |
|---|---|
| Agent enrolled & active | ✅ |
| RDP reachable (nmap) | ✅ port 3389 open |
| Brute force executed (hydra) | ✅ 10 attempts, 0 success |
| Wazuh alert generated | ✅ rule 60122, level 5 |
| MITRE ATT&CK auto-mapped | ✅ T1110 – Brute Force |

## Lessons learned / gaps found

1. **Default Windows audit policy is not sufficient** — `Logon` success/failure auditing must be explicitly enabled, or Wazuh never sees 4624/4625 events at all.
2. **Account lockout policy was not configured** — in a production setting, this scenario should also trigger a lockout after N attempts (Account Lockout Threshold). Worth adding as a follow-up test and a custom Wazuh active-response rule.
3. **A clean negative result is still a detection win** — zero successful logins doesn't mean zero signal; 10 failed logons in under a minute from a single source is enough to alert on *before* any password succeeds.

## Next steps

- Add an **active response** rule in Wazuh to auto-block the source IP after N failed RDP logons.
- Re-run with a password that *is* in the list and `Testuser` added to Remote Desktop Users, to capture the full attack chain through to T1078 (Valid Accounts) and an interactive session.
- Feed this alert into the **n8n + LLM** triage pipeline for automated severity scoring and a plain-English incident summary.
- Expand coverage with **Atomic Red Team** tests for T1110 sub-techniques (password spraying, credential stuffing).

---

*Part of the [wazuh-soc-homelab](../../) detection-engineering portfolio.*
