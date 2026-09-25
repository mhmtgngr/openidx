#!/usr/bin/env python3
"""Summarize one conformance run: what each module of each plan returned, and
which failures and warnings a dated waiver covers.

It asks the running suite (its REST API) rather than parsing the runner's
console output: for every plan listed in plans.txt it takes the newest plan of
that name and variant, and for every module in it the latest instance, its
status and result, and the FAILURE and WARNING entries of its log.

Waivers are read from waivers/expected-failures.json and
waivers/expected-skips.json, the files run-test-plan.py is given, and matched
the way run-test-plan.py matches them. The runner's exit code decides whether
the job is red; this report says why, and names waivers that no longer match
anything (the runner fails on those too).

Writes to --out:
  results.json   everything above, for tooling
  summary.md     for $GITHUB_STEP_SUMMARY
  issue.md       the body of the tracking issue (see the workflow's report job)

Standard library only. It never fails the job itself: with the suite
unreachable it reports that no results were produced.
"""

import argparse
import datetime
import fnmatch
import json
import os
import pathlib
import re
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request

HERE = pathlib.Path(__file__).resolve().parent
PLAN_LINE = re.compile(r"^(?P<name>[A-Za-z0-9_-]+)(?P<variants>(\[[^\]]+\])*)\s+(?P<config>\S+)$")
VARIANT = re.compile(r"\[([^=\]]+)=([^\]]*)\]")

PROFILE_NAMES = {
    "oidcc-basic-certification-test-plan": "Basic OP",
    "oidcc-config-certification-test-plan": "Config OP",
    "oidcc-rp-initiated-logout-certification-test-plan": "RP-Initiated Logout OP",
    "oidcc-backchannel-rp-initiated-logout-certification-test-plan": "Back-Channel Logout OP",
}


def read_plans(path):
    plans = []
    for raw in path.read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        m = PLAN_LINE.match(line)
        if not m:
            raise SystemExit("summarize: cannot read plans.txt line: " + line)
        variants = {k: v.replace("\\ ", " ") for k, v in VARIANT.findall(m.group("variants"))}
        plans.append({"name": m.group("name"), "variants": variants, "config": m.group("config")})
    return plans


def read_waivers(path):
    try:
        data = json.loads(path.read_text() or "[]")
    except (OSError, ValueError) as err:
        raise SystemExit("summarize: cannot read %s: %s" % (path, err))
    for entry in data:
        entry["_used"] = False
    return data


class Suite:
    def __init__(self, base, cafile):
        self.base = base.rstrip("/") + "/"
        self.context = ssl.create_default_context(cafile=cafile) if cafile else ssl.create_default_context()

    def get(self, path, **params):
        url = self.base + path
        if params:
            url += "?" + urllib.parse.urlencode(params)
        with urllib.request.urlopen(url, timeout=60, context=self.context) as resp:
            return json.loads(resp.read())


def variant_matches(expected, actual):
    if expected == "*":
        return True
    if not isinstance(expected, dict):
        return False
    return all(k in actual and actual[k] == v for k, v in expected.items())


def waiver_applies(entry, test_name, config, variant):
    return (fnmatch.fnmatch(test_name, entry.get("test-name", ""))
            and fnmatch.fnmatch(config, entry.get("configuration-filename", ""))
            and variant_matches(entry.get("variant"), variant or {}))


def module_findings(log):
    """FAILURE and WARNING entries, each with the block it happened in."""
    blocks = {}
    findings = []
    for entry in log:
        if entry.get("startBlock") and entry.get("src") == "-START-BLOCK-":
            blocks[entry.get("blockId")] = entry.get("msg", "")
            continue
        result = entry.get("result")
        if result not in ("FAILURE", "WARNING"):
            continue
        findings.append({
            "result": result,
            "condition": entry.get("src", ""),
            "block": blocks.get(entry.get("blockId"), ""),
            "message": " ".join(str(entry.get("msg", "")).split())[:200],
            "requirements": entry.get("requirements", []),
        })
    return findings


def classify(module, failures, skips, config):
    """Apply the waivers to one module, in place."""
    name, variant = module["test_name"], module["variant"]
    applicable = [w for w in failures if waiver_applies(w, name, config, variant)]
    for finding in module["findings"]:
        finding["waived"] = False
        for waiver in applicable:
            if waiver.get("condition") != finding["condition"]:
                continue
            if waiver.get("current-block") not in ("*", finding["block"]):
                continue
            if waiver.get("expected-result") != finding["result"].lower():
                continue
            waiver["_used"] = True
            finding["waived"] = True
            finding["waiver"] = {k: waiver.get(k) for k in ("waived-on", "tracking", "comment")}
            break
    module["expected_skip"] = False
    for waiver in skips:
        if waiver_applies(waiver, name, config, variant) and module["result"] in ("SKIPPED", "FAILED"):
            waiver["_used"] = True
            module["expected_skip"] = True

    unwaived = [f for f in module["findings"] if not f["waived"]]
    if module["status"] not in ("FINISHED", "INTERRUPTED"):
        module["outcome"] = "did not complete"
    elif module["result"] == "SKIPPED":
        module["outcome"] = "skipped (waived)" if module["expected_skip"] else "skipped"
    elif unwaived:
        module["outcome"] = "failed" if any(f["result"] == "FAILURE" for f in unwaived) else "warning"
    elif module["findings"]:
        module["outcome"] = "passed with waivers"
    elif module["result"] == "REVIEW":
        module["outcome"] = "passed (screenshot to review)"
    elif module["result"] == "PASSED":
        module["outcome"] = "passed"
    else:
        module["outcome"] = module["result"].lower() if module["result"] else "unknown"
    module["problem"] = module["outcome"] in ("did not complete", "skipped", "failed", "warning", "unknown")


def collect(suite, plans, failures, skips):
    results = []
    for spec in plans:
        entry = {"plan": spec["name"], "profile": PROFILE_NAMES.get(spec["name"], spec["name"]),
                 "variants": spec["variants"], "config": spec["config"], "modules": []}
        listing = suite.get("api/plan", plan=spec["name"], length=50, order="started,desc")
        chosen = None
        for plan in listing.get("data", []):
            if variant_matches(spec["variants"], plan.get("variant") or {}):
                chosen = plan
                break
        if chosen is None:
            entry["error"] = "the suite has no plan of this name and variant: it was not created"
            results.append(entry)
            continue
        entry["plan_id"] = chosen.get("_id")
        for mod in chosen.get("modules", []):
            instances = mod.get("instances") or []
            module = {"test_name": mod.get("testModule"), "variant": mod.get("variant") or {},
                      "status": "NOT RUN", "result": "", "findings": []}
            if instances:
                test_id = instances[-1]
                info = suite.get("api/info/" + test_id)
                module.update({"test_id": test_id, "status": info.get("status", ""),
                               "result": info.get("result") or "", "variant": info.get("variant") or module["variant"]})
                module["findings"] = module_findings(suite.get("api/log/" + test_id))
            classify(module, failures, skips, spec["config"])
            entry["modules"].append(module)
        results.append(entry)
    return results


def neutral(text):
    # Suite messages end up in an issue body: no mentions, no markup breakouts.
    return text.replace("@", "@​").replace("|", "\\|").replace("`", "'")


def render_summary(report):
    lines = ["# OpenID conformance run", ""]
    lines.append("Suite %s. OpenIDX commit `%s`. Run finished %s." % (
        report["suite"], report["commit"] or "unknown", report["finished"]))
    if report.get("run_url"):
        lines.append("[Workflow run](%s); the per-module logs are in the `oidc-conformance-results` artifact." % report["run_url"])
    lines.append("")
    lines.append("Overall: **%s**. The runner %s." % (report["status"], report["runner"]))
    lines.append("")
    if report.get("error"):
        lines += ["No results were produced: " + report["error"], ""]
    for plan in report["plans"]:
        lines.append("## %s (`%s`)" % (plan["profile"], plan["plan"]))
        lines.append("")
        if plan.get("error"):
            lines += [plan["error"], ""]
            continue
        counts = {}
        for m in plan["modules"]:
            counts[m["outcome"]] = counts.get(m["outcome"], 0) + 1
        lines.append(", ".join("%d %s" % (n, k) for k, n in sorted(counts.items())) or "no modules")
        lines.append("")
        lines.append("| Module | Result | Unwaived failures and warnings |")
        lines.append("| --- | --- | --- |")
        for m in plan["modules"]:
            problems = ["%s `%s`%s" % (f["result"], f["condition"], (": " + neutral(f["message"])) if f["message"] else "")
                        for f in m["findings"] if not f["waived"]]
            lines.append("| `%s` | %s | %s |" % (m["test_name"], m["outcome"], "<br>".join(problems) or ""))
        lines.append("")
    if report["stale_waivers"]:
        lines.append("## Waivers that matched nothing")
        lines.append("")
        lines.append("Each of these no longer describes this run; delete it, or correct it:")
        lines.append("")
        for w in report["stale_waivers"]:
            lines.append("- `%s` %s `%s` (waived %s, %s)" % (w.get("test-name"), w.get("expected-result", "skip"),
                                                            w.get("condition", ""), w.get("waived-on"), w.get("tracking")))
        lines.append("")
    return "\n".join(lines) + "\n"


def render_issue(report):
    lines = ["The nightly OpenID conformance run (`.github/workflows/oidc-conformance.yml`) has "
             "failures that no dated waiver covers. This issue is updated by every nightly run "
             "on `main` and closed by the first one that passes.", ""]
    lines.append("Latest run: %s (%s), suite %s, OpenIDX `%s`." % (
        report.get("run_url") or "(no URL)", report["finished"], report["suite"], report["commit"] or "unknown"))
    lines.append("")
    if report.get("error"):
        lines += ["No results were produced: " + report["error"], ""]
    for plan in report["plans"]:
        if plan.get("error"):
            lines += ["- **%s**: %s" % (plan["profile"], plan["error"])]
            continue
        bad = [m for m in plan["modules"] if m["problem"]]
        if not bad:
            continue
        lines.append("### %s (`%s`)" % (plan["profile"], plan["plan"]))
        lines.append("")
        for m in bad:
            lines.append("- `%s`: %s" % (m["test_name"], m["outcome"]))
            for f in m["findings"]:
                if not f["waived"]:
                    lines.append("  - %s `%s`%s" % (f["result"], f["condition"],
                                                    (": " + neutral(f["message"])) if f["message"] else ""))
        lines.append("")
    if report["stale_waivers"]:
        lines.append("### Waivers that matched nothing")
        lines.append("")
        for w in report["stale_waivers"]:
            lines.append("- `%s` `%s` (waived %s, %s)" % (w.get("test-name"), w.get("condition", "skip"),
                                                        w.get("waived-on"), w.get("tracking")))
        lines.append("")
    lines += [
        "Each item is either an OpenIDX defect to fix, or a known deviation to waive: add a dated "
        "entry to `test/conformance/waivers/expected-failures.json` (or `expected-skips.json`) "
        "with the reason, and record it under Known deviations in `docs/OAUTH-OIDC.md`.",
        "",
    ]
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--out", required=True)
    parser.add_argument("--server", default="https://localhost.emobix.co.uk:8443")
    parser.add_argument("--cafile", default="", help="CA that signed the suite's certificate")
    parser.add_argument("--plans", default=str(HERE / "plans.txt"))
    parser.add_argument("--waivers-dir", default=str(HERE / "waivers"))
    parser.add_argument("--runner-outcome", default="", help="outcome of the run-plans step")
    parser.add_argument("--run-url", default="")
    args = parser.parse_args()

    out = pathlib.Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    plans = read_plans(pathlib.Path(args.plans))
    failures = read_waivers(pathlib.Path(args.waivers_dir) / "expected-failures.json")
    skips = read_waivers(pathlib.Path(args.waivers_dir) / "expected-skips.json")

    suite_tag = ""
    env_file = HERE / "suite.env"
    if env_file.exists():
        for line in env_file.read_text().splitlines():
            if line.startswith("CONFORMANCE_SUITE_TAG="):
                suite_tag = line.split("=", 1)[1].strip()

    report = {
        "suite": suite_tag or "unknown",
        "commit": os.environ.get("GITHUB_SHA", ""),
        "finished": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        "run_url": args.run_url,
        "runner": {"success": "passed", "failure": "failed", "": "did not run"}.get(
            args.runner_outcome, args.runner_outcome),
        "plans": [],
        "stale_waivers": [],
    }
    try:
        report["plans"] = collect(Suite(args.server, args.cafile or None), plans, failures, skips)
    except (urllib.error.URLError, OSError, ValueError) as err:
        report["error"] = "the suite at %s could not be read (%s)" % (args.server, err)

    if not report.get("error"):
        report["stale_waivers"] = [{k: v for k, v in w.items() if k != "_used"}
                                   for w in failures + skips if not w["_used"]]
    problems = sum(1 for p in report["plans"] for m in p.get("modules", []) if m["problem"])
    problems += sum(1 for p in report["plans"] if p.get("error"))
    problems += len(report["stale_waivers"])
    if report.get("error") or args.runner_outcome != "success" and problems == 0:
        # The runner failed for a reason this report cannot see (it stopped
        # early, or it could not start): never call that a pass.
        report["status"] = "incomplete"
    elif problems:
        report["status"] = "failed"
    else:
        report["status"] = "passed"
    report["problems"] = problems

    (out / "results.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    (out / "summary.md").write_text(render_summary(report))
    (out / "issue.md").write_text(render_issue(report))
    print("summarize: %s, %d problem(s); wrote results.json, summary.md and issue.md to %s"
          % (report["status"], problems, out))


if __name__ == "__main__":
    sys.exit(main())
