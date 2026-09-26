import argparse
import json
import os
import sys
import time

from .core import auditor, cracker, hashes, report, wordlists

MODE32_CHOICES = ("auto", "md5", "ntlm")


def _load_targets(path, force32=None):
    targets = []
    seen = set()
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            t = hashes.identify_line(line, force32=force32)
            if not t:
                continue
            key = (t["token"], "/".join(t["algos"]), t.get("salt"))
            if key in seen:
                continue
            seen.add(key)
            t["pos"] = len(targets) + 1
            targets.append(t)
    if not targets:
        raise SystemExit("No recognizable hashes found in {}".format(path))
    return targets


def cmd_identify(args):
    force = {"md5": "MD5", "ntlm": "NTLM"}.get(args.force32)
    for path in args.files:
        targets = _load_targets(path, force32=force)
        for t in targets:
            print("{}\t{}\t{}\t{}".format(t["pos"], "/".join(t["algos"]), t["token"], t.get("salt") or "-"))
        print("{}: {} target(s)".format(path, len(targets)), file=sys.stderr)


def cmd_crack(args):
    force = {"md5": "MD5", "ntlm": "NTLM"}.get(args.force32)
    targets = _load_targets(args.files[0], force32=force)
    words = wordlists.load_wordlist(args.wordlist) if args.wordlist else []
    mode = "mask" if args.mask else ("rules" if args.rules else "wordlist")
    if mode in ("wordlist", "rules") and not words:
        print("No wordlist loaded; use --wordlist PATH", file=sys.stderr)
        return 1

    def progress(d):
        print(
            "\rtried {:,} rate {:.0f}/s found {}        ".format(
                d["tried"], d["rate"] or 0, d["found"]
            ),
            end="",
            file=sys.stderr,
        )

    crk = cracker.Cracker(targets, workers=args.workers)
    stats = crk.run(
        mode,
        words=words,
        charset=args.charset,
        min_len=args.min_len,
        max_len=args.max_len,
        progress=progress,
    )
    print(file=sys.stderr)
    if args.json:
        print(json.dumps({"stats": stats, "results": stats["found_map"]}, indent=2))
    else:
        for token, info in stats["found_map"].items():
            print("{}:\t{}".format(info["algo"], info["candidate"]))
        print(
            "{} / {} cracked | {} attempted | {:.1f}s".format(
                len(stats["found_map"]), len(targets), stats["attempted"], stats["elapsed_s"]
            ),
            file=sys.stderr,
        )
    return 0


def cmd_audit(args):
    block = wordlists.common_blocklist() if args.blocklist else None
    pws = [args.password] if args.password else wordlists.load_wordlist(args.file)
    rows = []
    for pw in pws:
        rows.append(auditor.analyze(pw, blocklist=block, algo=args.algo))
    if args.json:
        print(json.dumps(rows, indent=2))
    else:
        for r in rows:
            if args.password:
                print(
                    "{} | entropy {} bits | score {} | {} | crack@{}: {}".format(
                        r["password"],
                        r["bits"],
                        r["score"],
                        r["label"],
                        args.algo,
                        r["estimates"].get(args.algo, "?"),
                    )
                )
            else:
                print(
                    "{}: {} ({} bits, score {})".format(r["password"], r["label"], r["bits"], r["score"])
                )
    return 0


def _load_json_file(path):
    with open(path, "rb") as fh:
        raw = fh.read()
    if raw.startswith(b"\xff\xfe") or raw.startswith(b"\xfe\xff"):
        return json.loads(raw.decode("utf-16"))
    return json.loads(raw.decode("utf-8-sig"))


def cmd_report(args):
    force = {"md5": "MD5", "ntlm": "NTLM"}.get(args.force32)
    targets = _load_targets(args.files[0], force32=force)
    results = {}
    if args.results:
        data = _load_json_file(args.results)
        for token, info in data.items():
            results[token.lower()] = {"candidate": info.get("candidate", ""), "algo": info.get("algo", "")}
    items = []
    for t in targets:
        info = results.get(t["token"].lower())
        items.append(
            {
                "pos": t["pos"],
                "token": t["token"],
                "algos": t["algos"],
                "salt": t.get("salt") or "",
                "candidate": (info or {}).get("candidate", ""),
                "algo_matched": (info or {}).get("algo", ""),
            }
        )
    summary = {
        "targets": len(items),
        "cracked": sum(1 for i in items if i["candidate"]),
        "unresolved": sum(1 for i in items if not i["candidate"]),
        "scope": "OWN / AUTHORIZED DATA ONLY",
    }
    meta = {
        "tool": "PasswordGuardian",
        "version": "1.0.0",
        "operator": args.operator,
        "session_id": args.session or "cli-session",
        "workspace": os.path.abspath("."),
        "generated_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    data = {"meta": meta, "summary": summary, "items": items}
    os.makedirs(args.out, exist_ok=True)
    base = os.path.join(args.out, "report_cli")
    report.write_csv(base + ".csv", items)
    report.write_json(base + ".json", data)
    html_doc = report.build_html(meta, summary, items)
    with open(base + ".html", "w", encoding="utf-8") as fh:
        fh.write(html_doc)
    print(base + ".html / .csv / .json written")
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="passwordguardian",
        description="Password strength auditor & wordlist cracker (own hashes only).",
    )
    sub = parser.add_subparsers(dest="command")

    p_id = sub.add_parser("identify", help="detect algorithms of hash lines in a file")
    p_id.add_argument("files", nargs="+")
    p_id.add_argument("--force32", choices=MODE32_CHOICES, default="auto")
    p_id.set_defaults(func=cmd_identify)

    p_cr = sub.add_parser("crack", help="run a wordlist/rules/mask attack")
    p_cr.add_argument("files", nargs="+")
    p_cr.add_argument("--wordlist", "-w")
    p_cr.add_argument("--rules", action="store_true")
    p_cr.add_argument("--mask", action="store_true")
    p_cr.add_argument("--charset", default="abcdefghijklmnopqrstuvwxyz0123456789")
    p_cr.add_argument("--min-len", type=int, default=4)
    p_cr.add_argument("--max-len", type=int, default=4)
    p_cr.add_argument("--workers", type=int, default=4)
    p_cr.add_argument("--force32", choices=MODE32_CHOICES, default="auto")
    p_cr.add_argument("--json", action="store_true")
    p_cr.set_defaults(func=cmd_crack)

    p_au = sub.add_parser("audit", help="score password strength (NIST SP 800-63B)")
    p_au.add_argument("--password", "-p")
    p_au.add_argument("--file", "-f", help="audit a list of own plaintexts, one per line")
    p_au.add_argument("--algo", default="MD5")
    p_au.add_argument("--blocklist", action="store_true", default=True)
    p_au.add_argument("--json", action="store_true")
    p_au.set_defaults(func=cmd_audit)

    p_rp = sub.add_parser("report", help="build HTML/CSV/JSON report")
    p_rp.add_argument("files", nargs="+")
    p_rp.add_argument("--out", required=True)
    p_rp.add_argument("--operator", required=True)
    p_rp.add_argument("--session")
    p_rp.add_argument("--results", help="optional JSON map token->{candidate,algo}")
    p_rp.add_argument("--force32", choices=MODE32_CHOICES, default="auto")
    p_rp.set_defaults(func=cmd_report)

    args = parser.parse_args(argv)
    if not args.command:
        parser.print_help()
        return 0
    return args.func(args) or 0


if __name__ == "__main__":
    raise SystemExit(main())