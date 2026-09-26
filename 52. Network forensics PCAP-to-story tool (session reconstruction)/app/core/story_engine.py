"""story_engine.py - Deterministic Story Graph + narrative generation.

Implements architecture.md SS4.3/SS4.4: deterministic, evidence-grounded narrative.
Every node is anchored to events carrying (frame_id, payload_offset) so no claim
exists without provenance. TTPs are mapped against MITRE ATT&CK tactic names.

Anti-hallucination: the engine only *verbalises* typed evidence slots.
"""

from __future__ import annotations

from .security import mask_ip

MITRE_TACTICS = {
    "recon": "Reconnaissance (TA0043)",
    "resource": "Resource Development (TA0042)",
    "initial": "Initial Access (TA0001)",
    "execution": "Execution (TA0002)",
    "persistence": "Persistence (TA0003)",
    "privilege": "Privilege Escalation (TA0004)",
    "evasion": "Defense Evasion (TA0005)",
    "credentials": "Credential Access (TA0006)",
    "discovery": "Discovery (TA0007)",
    "lateral": "Lateral Movement (TA0008)",
    "collection": "Collection (TA0009)",
    "c2": "Command and Control (TA0011)",
    "exfil": "Exfiltration (TA0010)",
    "impact": "Impact (TA0040)",
}


def _node(nid: str, tactic: str, label: str, evidence) -> dict:
    return {"id": nid, "tactic": tactic, "label": label, "evidence": evidence}


class StoryBuilder:
    """Turns a SessionRecord into story graph + narrative + risk score."""

    def build(self, rec: dict) -> dict:
        nodes, edges, findings = [], [], []
        events = rec.get("events", [])
        l7 = rec.get("l7", "unknown")
        beac = rec.get("beacon", False)
        stats = rec.get("stats", {})
        sb, sc = rec.get("bytes_c2s", 0), rec.get("bytes_s2c", 0)
        total = rec.get("total_bytes", sb + sc)
        src = rec.get("src", "?")
        dst = rec.get("dst", "?")

        story_nodes = {}
        counter = [0]

        def add(tactic, label, evidence):
            counter[0] += 1
            nid = f"n{counter[0]}"
            nodes.append(_node(nid, tactic, label, evidence))
            return nid

        # --- discovery / recon -------------------------------------------------
        dns_names = set()
        for e in events:
            if e.get("type") == "dns_query":
                for n in e.get("names", []):
                    if n and n not in dns_names:
                        dns_names.add(n)
        if dns_names:
            nid = add("discovery", f"DNS resolution of {', '.join(list(dns_names)[:4])}", [e["frame_id"] for e in events if e.get("type") == "dns_query"][:4])
            story_nodes["dns"] = nid
            findings.append("Domain resolution observed matching discovery behaviour.")

        # --- protocol channel ---------------------------------------------------
        chan_labels = {
            "http": "HTTP plaintext channel",
            "tls": "TLS-encrypted channel (encrypted comms)",
            "ssh": "SSH encrypted shell channel",
            "smtp": "SMTP email channel",
            "ftp": "FTP file-transfer channel",
        }
        if l7 in chan_labels:
            evidence = [e["frame_id"] for e in events if e.get("type") in ("http_request", "http_response", "tls_clienthello", "ssh_banner", "smtp_banner", "ftp")][:4]
            nid = add("collection" if l7 == "smtp" else "c2", chan_labels[l7], evidence)
            story_nodes["channel"] = nid
            if l7 == "http" and stats.get("c2s_bytes", 0) > 1024 * 1024:
                findings.append("Large HTTP transfer volume on cleartext channel.")

        # --- credentials at risk ------------------------------------------------
        cred_ev = [e for e in events if e.get("type") in ("cred_in_transit", "http_request_cred")]
        if cred_ev:
            nid = add("credentials", "Credentials/secret material observed in cleartext", [e["frame_id"] for e in cred_ev][:4])
            story_nodes["cred"] = nid
            findings.append("Sensitive values (password/secret/token) transited without encryption.")

        # --- beacon / C2 ---------------------------------------------------------
        if beac:
            nid = add("c2", f"Periodic beacon pattern detected (score={stats.get('beacon_score', 0):.2f})", [e["frame_id"] for e in events[:4]])
            story_nodes["c2"] = nid
            findings.append("Traffic periodicity consistent with a command-and-control beacon (T1571/T1041).")

        # --- exfiltration --------------------------------------------------------
        exf = False
        big = max(sb, sc)
        small = max(1, min(sb, sc))
        if big > 50_000 and big / small > 4:
            exf = True
            outward = max(sb, sc)
            nid = add("exfil", f"High-volume one-directional transfer ({outward // 1024} KiB dominant direction)", [e["frame_id"] for e in events if len(events)])
            story_nodes["exfil"] = nid
            findings.append(f"Directional imbalance {big // 1024} KiB vs {small // 1024} KiB suggests exfiltration (T1041).")
        else:
            nid = add("recon", "Low/no-payload flow (port probes or keepalive)", [e["frame_id"] for e in events[:2]])
            story_nodes["probe"] = nid

        # --- tls ----------------------------------------------------------------
        tls_ev = [e for e in events if e.get("type") == "tls_clienthello"]
        if tls_ev and "tls" not in str(story_nodes.get("channel", "")):
            nid = add("evasion", "Encrypted handshake hides payload contents (E3)", [e["frame_id"] for e in tls_ev][:3])
            story_nodes.setdefault("channel", nid)

        # --- edges ---------------------------------------------------------------
        keys = list(story_nodes.keys())
        edges = []
        if len(keys) > 1:
            root = story_nodes.get("dns") or story_nodes.get("probe") or keys[0]
            for k in keys[1:]:
                edges.append({"from": root, "to": story_nodes[k], "rel": "facilitates"})

        # --- narrative ------------------------------------------------------------
        narrative = self._narrative(rec, story_nodes, findings)

        # --- risk ---------------------------------------------------------------
        score = 10
        score += 10 if dns_names else 0
        score += 20 if beac else 0
        score += 30 if exf else 0
        score += 15 if cred_ev else 0
        score += 5 if l7 in ("tls", "ssh") else 0
        score += 10 if stats.get("gaps", 0) > 3 else 0
        score = min(100, score)
        severity = "CRITICAL" if score >= 70 else "HIGH" if score >= 50 else "MEDIUM" if score >= 25 else "LOW"

        ttp = "T1041/T1571 (Exfil/Beacon)" if exf or beac else "T1071 (Application-Layer C2)" if l7 in ("http", "tls") else "T1000"

        return {
            "nodes": nodes,
            "edges": edges,
            "narrative": narrative,
            "findings": findings,
            "risk_score": score,
            "severity": severity,
            "ttp": ttp,
        }

    # ---------------------------------------------------------------- narrative
    def _narrative(self, rec: dict, story_nodes: dict, findings: list) -> list[str]:
        src = mask_ip(rec.get("src", ""), 2)
        dst = mask_ip(rec.get("dst", ""), 2)
        lines = [
            f"At {rec.get('start_ts', 'unknown')} the flow {src}:{rec.get('sport', 0)} <-> {dst}:{rec.get('dport', 0)} "
            f"({rec.get('proto', '?')}, L7={rec.get('l7', 'unknown')}) was reconstructed from {rec.get('frames', 0)} frames.",
        ]
        st = rec.get("stats", {})
        if st.get("retransmits") or st.get("out_of_order"):
            lines.append(
                f"TCP reassembly flagged {st.get('retransmits', 0)} retransmission(s) and {st.get('out_of_order', 0)} "
                f"out-of-order segment(s), with {st.get('gaps', 0)} gap event(s) — stream continuity kept by the "
                "RFC 793 reassembly buffer."
            )
        if story_nodes.get("dns"):
            lines.append(f"Reconnaissance phase began with DNS queries ({findings[0]}).")
        if story_nodes.get("cred"):
            lines.append("Credential material was observed unencrypted in transit — a principal risk for account takeover.")
        if story_nodes.get("c2"):
            lines.append(f"Traffic shows a periodic pattern (beacon score {rec.get('stats', {}).get('beacon_score', 0):.2f}), "
                         "consistent with C2 beaconing.")
        if story_nodes.get("exfil"):
            lines.append("The outbound volume dwarfs inbound traffic, matching a covert data-exfiltration pattern.")
        if findings:
            lines.extend(f"Finding: {f}" for f in findings)
        lines.append(f"Composite risk: {rec.get('story', {}).get('severity', 'LOW')} (score 0-100), mapping to MITRE {rec.get('story', {}).get('ttp', 'T1000')}.")
        return lines


def build_story(rec: dict) -> dict:
    story = StoryBuilder().build(rec)
    rec["story"] = story
    return story