# 🛡️ AI Masterclass — Cybersecurity Projects Portfolio

A hands-on portfolio of **72 cybersecurity projects** spanning the full spectrum: network security → SOC/blue team → offensive security → red team & C2 → digital forensics → malware analysis → compliance → 3D visualization.

> ⚠️ **Educational use only.** Every tool here is designed for labs, owned systems, or explicitly authorized environments. Do not use against systems you do not have permission to test.

---

## 📊 At a Glance

| Category | Projects |
|---|---:|
| 🌐 Networking & Reconnaissance | 11 |
| 🖥️ SOC, Detection & Blue Team | 11 |
| ⚔️ Offensive Security & Exploitation | 9 |
| 🎯 Red Team & Adversary Simulation | 4 |
| 📡 C2 & Detection Engineering | 8 |
| 🔍 Digital Forensics & Incident Response | 8 |
| 🦠 Malware Analysis & Reverse Engineering | 11 |
| 📱 Secure Applications | 4 |
| 🌍 Security Visualization & Dashboards | 5 |
| 📋 Compliance & GRC | 1 |
| **Total** | **72** |

---

## 🌐 Networking & Reconnaissance

Network discovery, traffic analysis, and infrastructure tooling.

- [1. Subnet Mask Calculator and VLSM planner](<1. Subnet Mask Calculator and VLSM planner_Completed>)
- [2. Packet sniffer](<2. packet-sniffer_Completed>)
- [3. ARP scanner — live-host discovery tool](<3. ARP scanner live-host discovery tool>)
- [4. Portscanner](<4. portscanner>)
- [5. Simple DNS resolver + DNS cache poisoning lab demo (isolated network only)](<5. Simple DNS resolver + DNS cache poisoning lab demo (isolated network only)>)
- [6. Proxy server GUI](<6. proxy-server-gui>)
- [7. Bandwidth monitor & traffic visualizer dashboard](<7. Bandwidth monitor & traffic visualizer dashboard>)
- [8. Network topology auto-mapper (SNMP + ARP + traceroute)](<8. Network topology auto-mapper (SNMP + ARP + traceroute)>)
- [9. VPN tunnel builder (WireGuard automation script)](<9. VPN tunnel builder (WireGuard automation script)>)
- [10. Load balancer simulator with health checks](<10. Load balancer simulator with health checks>)
- [66. Network traffic monitor app (on-device, per-app bandwidth)](<66. Network traffic monitor app (on-device, per-app bandwidth)>)

## 🖥️ SOC, Detection & Blue Team

Monitoring, alerting, hardening, and incident-response automation.

- [11. Lightweight SIEM log correlator (ingest → normalize → alert)](<11. Lightweight SIEM log correlator (ingest → normalize → alert>)
- [12. Host-based intrusion detection agent (file integrity + process monitor)](<12. Host-based intrusion detection agent (file integrity + process monitor)>)
- [13. Custom Wazuh/OSSEC detection rule pack for a specific attack chain](<13. Custom WazuhOSSEC detection rule pack for a specific attack chain>)
- [14. Firewall rule auditor & misconfiguration checker](<14. Firewall rule auditor & misconfiguration checker>)
- [15. Honeypot (SSH/HTTP) with attacker fingerprinting](<15. Honeypot (SSH HTTP) with attacker fingerprinting>)
- [16. Threat-intel feed aggregator (IOC ingestion + auto-blocklist)](<16. Threat-intel feed aggregator (IOC ingestion + auto-blocklist)>)
- [18. SOC alert triage dashboard (severity scoring + dedup)](<18. SOC alert triage dashboard (severity scoring + dedup)>)
- [19. Endpoint hardening & compliance checker (CIS benchmark automation)](<19.Endpoint hardening & compliance checker (CIS benchmark automation)>)
- [20. Log anonymizer with redactor for safe log sharing](<20. Log anonymizer with redactor for safe log sharing>)
- [21. Phishing email analyzer (header, URL, attachment triage tool)](<21. Phishing email analyzer (header, URL, attachment triage tool)>)
- [22. Automated incident response playbook runner (SOAR-lite)](<22. Automated incident response playbook runner (SOAR-lite)>)

## ⚔️ Offensive Security & Exploitation

Vulnerability assessment and penetration-testing utilities for authorized lab use.

- [23. Custom vulnerability scanner (banner grabbing + CVE matching)](<23. Custom vulnerability scanner (banner grabbing + CVE matching)>)
- [24. Password strength auditor & wordlist-based cracker (own hashes only)](<24. Password strength auditor & wordlist-based cracker (own hashes only)>)
- [25. Web app fuzzer for input validation testing](<25. Web app fuzzer for input validation testing>)
- [26. SQL injection detection tool (defensive-oriented, flags vulnerable params)](<26. SQL injection detection tool (defensive-oriented, flags vulnerable params)>)
- [27. XSS payload tester for your own lab web app](<27. XSS payload tester for your own lab web app>)
- [28. Reverse-engineering CTF challenge solver toolkit](<28. Reverse-engineering CTF challenge solver toolkit>)
- [29. Custom Burp Suite extension for a specific test case](<29. Custom Burp Suite extension for a specific test case>)
- [30. Wireless network auditor (WPA handshake capture in your own lab AP)](<30. Wireless network auditor (WPA handshake capture in your own lab AP)>)
- [31. Social engineering awareness simulator (internal phishing test platform)](<31. Social engineering awareness simulator (internal phishing test platform)>)

## 🎯 Red Team & Adversary Simulation

- [33. Active Directory attack path visualizer (BloodHound-style, lab domain)](<33. Active Directory attack path visualizer (BloodHound-style, lab domain)>)
- [34. Exploit development walkthrough — buffer overflow in a deliberately vulnerable lab binary](<34. Exploit development walkthrough buffer overflow in a deliberately vulnerable lab binary>)
- [35. Custom Metasploit module for a lab-only vulnerable service](<35. Custom Metasploit module for a lab-only vulnerable service>)
- [36. Red team engagement report generator (findings → CVSS → executive summary)](<36. Red team engagement report generator (findings → CVSS → executive summary)>)

## 📡 C2 & Detection Engineering

Build the adversary technique, then build the detection for it.

- [37. Minimal C2 architecture — beacon + listener over HTTP (educational skeleton)](<37. Minimal C2 architecture beacon + listener over HTTP (educational skeleton)>)
- [38. Traffic obfuscation techniques demo (domain fronting concepts, detection-focused)](<38. traffic obfuscation techniques demo (domain fronting concepts, detection-focused)>)
- [39. Agent check-in jitter and sleep implementation study](<39. Agent check-in jitter and sleep implementation study>)
- [40. C2 detection lab — build the C2, then build the Zeek/Suricata signatures that catch it](<40. C2 detection lab build the C2, then build the Zeek, Suricata signatures that catch it>)
- [41. Encrypted C2 channel demo (TLS-wrapped beacon) + traffic decryption for blue team study](<41. Encrypted C2 channel demo (TLS-wrapped beacon) + traffic decryption for blue team study>)
- [42. Persistence mechanism catalog + matching detection rules (registry, cron, services)](<42. Persistence mechanism catalog + matching detection rules (registry, cron, services)>)
- [43. Lateral movement simulation in an isolated AD lab + detection engineering exercise](<43. lateral movement simulation in an isolated AD lab + detection engineering exercise>)
- [44. Purple team capstone — red builds, blue detects, both document MITRE ATT&CK mapping](<44. Purple team capstone red builds, blue detects, both document MITRE ATT&CK mapping>)

## 🔍 Digital Forensics & Incident Response

Evidence acquisition, artifact parsing, and timeline reconstruction.

- [45. Disk image acquisition & hashing toolkit (chain-of-custody automation)](<45. Disk image acquisition & hashing toolkit (chain-of-custody automation)>)
- [47. Timeline builder from filesystem + log artifacts](<47. Timeline builder from filesystem + log artifacts>)
- [48. Deleted file recovery tool (FAT & NTFS carving)](<48. Deleted file recovery tool (FAT & NTFS carving)>)
- [49. Browser artifact extractor (history, cookies, cache parser)](<49. Browser artifact extractor (history, cookies, cache parser)>)
- [50. Windows Event Log correlation tool for intrusion timeline](<50. Windows Event Log correlation tool for intrusion timeline>)
- [51. Mobile device forensics workflow (Android backup, logical extraction, lab device)](<51. Mobile device forensics workflow (Android backup, logical extraction, lab device)>)
- [52. Network forensics PCAP-to-story tool (session reconstruction)](<52. Network forensics PCAP-to-story tool (session reconstruction)>)
- [54. Ransomware incident tabletop simulator + IR runbook builder](<54. Ransomware incident tabletop simulator + IR runbook builder>)

> 🔗 Also see [46. Memory forensics analyzer (Volatility plugin and workflow)](https://github.com/mohsin539/memory-forensics-analyzer) — maintained as a standalone repository.

## 🦠 Malware Analysis & Reverse Engineering

Static/dynamic analysis, classification, and IOC extraction (public lab samples only).

- [17. YARA rule generator from malware sample sets](<17. YARA rule generator from malware sample sets>)
- [55. Static analysis pipeline (strings, PE header parsing, hash lookups)](<55.Static analysis pipeline (strings, PE header parsing, hash lookups)>)
- [56. Dynamic analysis sandbox (isolated VM + behavior logging)](<56. Dynamic analysis sandbox (isolated VM + behavior logging)>)
- [57. YARA-based malware family classifier](<57. YARA-based malware family classifier>)
- [58. Unpacking/de-obfuscation practice on public malware samples (MalwareBazaar, lab VM)](<58. Unpackingde-obfuscation practice on public malware samples (MalwareBazaar, lab VM)>)
- [59. API call sequence visualizer for a sample's behavior](<59. API call sequence visualizer for a sample's behavior>)
- [60. Malware persistence technique cataloger (auto-extract IOCs from a sample)](<60. Malware persistence technique cataloger (auto-extract IOCs from a sample)>)
- [61. Ransomware behavior analysis report (encryption pattern study, sample from public repo)](<61. Ransomware behavior analysis report (encryption pattern study, sample from public repo)>)
- [62. C2 beacon extractor from a captured malware sample's network traffic](<62. C2 beacon extractor from a captured malware sample's network traffic>)
- [63. Malware analysis automation pipeline (submit sample → static + dynamic report)](<63. Malware analysis automation pipeline (submit sample → static + dynamic report)>)
- [64. Threat actor TTP profiler from analyzed sample set (MITRE ATT&CK mapping)](<64. Threat actor TTP profiler from analyzed sample set (MITRE ATT&CK mapping)>)

## 📱 Secure Applications

- [65. Secure note-taking app (local encryption, biometric lock)](<65. Secure note-taking app (local encryption, biometric lock)>)
- [67. Mobile MDM-lite device compliance checker app](<67. Mobile MDM-lite device compliance checker app>)
- [68. Android malware analysis companion app (permission auditor for installed apps)](<68. Android malware analysis companion app (permission auditor for installed apps)>)
- [78. WebXR security awareness training module](<78. WebXR security awareness training module>)

## 🌍 Security Visualization & Dashboards

- [69. Real-time SOC dashboard with 3D network topology visualization](<69. Real-time SOC dashboard with 3D network topology visualization>)
- [70. Interactive 3D network attack-path visualizer (web-based BloodHound viewer)](<70. Interactive 3D network attack-path visualizer (web-based BloodHound viewer)>)
- [71. WebGL-based data breach world map (live threat feed visualization)](<71. WebGL-based data breach world map (live threat feed visualization)>)
- [76. 3D product configurator (drag/rotate/customize)](<76. 3D product configurator (dragrotatecustomize)>)
- [79. 3D CTF scoreboard (leaderboard visualization)](<79 3D CTF scoreboard (leaderboard visualization)>)

## 📋 Compliance & GRC

- [72. Compliance automation suite (ISO 27001 + Bangladesh Bank ICT Guidelines control mapper)](<72. Compliance automation suite (ISO 27001  Bangladesh Bank ICT Guidelines control mapper)>)

---

## 📝 Notes

- Project numbers **32** and **53** are reserved but not yet published.
- Each project folder contains its own `README.md` / `architecture.md` with setup instructions.
- Tech stack: Python (TkGUI/PySide), Node.js/TypeScript (React, Vite, WebGL/Three.js), plus integrations with Wazuh, Suricata, Zeek, Volatility, YARA, and Burp Suite.

## ⚖️ Disclaimer

This repository is for **educational and authorized security testing purposes only**. All offensive tools are scoped to lab environments, isolated networks, or systems you own. The author is not responsible for misuse.
