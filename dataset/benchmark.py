"""Benchmark harness for the Secure Coding Assistant detection engine.

Runs the detector over the labeled dataset and reports recall/precision per
vulnerability type plus an overall summary. Direct import of the backend
scanner (no server required).

Run:  python -m dataset.benchmark
Output: dataset/benchmark_results.json, dataset/benchmark_results.md
"""
import json
import os
import sys
from collections import defaultdict

HERE = os.path.dirname(os.path.abspath(__file__))
# Ensure repo root is importable (backend package).
REPO_ROOT = os.path.dirname(HERE)
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from backend.detection_engine.scanner import run_scan  # noqa: E402
from backend.schemas import ScanRequest, VulnType  # noqa: E402

SECURITY_TYPES = {
    VulnType.SQL_INJECTION.value,
    VulnType.COMMAND_INJECTION.value,
    VulnType.HARDCODED_SECRET.value,
    VulnType.XSS.value,
}


def detect(code: str):
    """Return the set of detected security vuln_types for a code snippet."""
    try:
        result = run_scan(ScanRequest(code=code))
    except Exception as e:  # defensive: never let one sample break the run
        return {"__error__": str(e)}
    detected = set()
    for issue in result.issues:
        detected.add(issue.vuln_type.value)
    return detected


def main():
    samples_path = os.path.join(HERE, "samples.json")
    with open(samples_path, encoding="utf-8") as f:
        samples = json.load(f)

    # Accumulators per expected type
    tp = defaultdict(int)
    fn = defaultdict(int)
    fp = defaultdict(int)
    tn = defaultdict(int)

    errors = []
    per_sample = []

    for s in samples:
        vtype = s["vuln_type"]
        label = s["label"]
        expected = s.get("expected_vuln_type")
        detected = detect(s["code"])

        if "__error__" in detected:
            errors.append({"id": s["id"], "error": detected["__error__"]})
            continue

        if label == "vulnerable":
            if expected in detected:
                tp[vtype] += 1
                outcome = "TP"
            else:
                fn[vtype] += 1
                outcome = "FN"
        else:  # secure -> expected is None
            # A false positive is any detected SECURITY issue.
            sec_detected = detected & SECURITY_TYPES
            if sec_detected:
                fp[vtype] += 1
                outcome = "FP"
            else:
                tn[vtype] += 1
                outcome = "TN"

        per_sample.append({
            "id": s["id"], "vuln_type": vtype, "label": label,
            "detected": sorted(detected), "outcome": outcome,
        })

    # Metrics
    def metrics(t, f):
        precision = tp[t] / (tp[t] + fp[t]) if (tp[t] + fp[t]) else 1.0
        recall = tp[t] / (tp[t] + fn[t]) if (tp[t] + fn[t]) else 1.0
        f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0
        return precision, recall, f1

    results = {"per_type": {}, "overall": {}, "errors": errors}
    all_tp = all_fn = all_fp = all_tn = 0
    for t in SECURITY_TYPES:
        p, r, f1 = metrics(t, fp[t])
        results["per_type"][t] = {
            "TP": tp[t], "FN": fn[t], "FP": fp[t], "TN": tn[t],
            "precision": round(p, 4), "recall": round(r, 4), "f1": round(f1, 4),
        }
        all_tp += tp[t]; all_fn += fn[t]; all_fp += fp[t]; all_tn += tn[t]

    # Overall: aggregate across types (macro over vulnerable samples)
    tot_vuln = all_tp + all_fn
    overall_recall = all_tp / tot_vuln if tot_vuln else 0.0
    overall_precision = all_tp / (all_tp + all_fp) if (all_tp + all_fp) else 1.0
    overall_f1 = (2 * overall_precision * overall_recall / (overall_precision + overall_recall)) if (overall_precision + overall_recall) else 0.0
    results["overall"] = {
        "TP": all_tp, "FN": all_fn, "FP": all_fp, "TN": all_tn,
        "total_vulnerable": tot_vuln, "total_secure": all_tn + all_fp,
        "recall": round(overall_recall, 4),
        "precision": round(overall_precision, 4),
        "f1": round(overall_f1, 4),
    }

    # Write JSON
    json_path = os.path.join(HERE, "benchmark_results.json")
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)

    # Write Markdown summary
    md = ["# Benchmark Results", "",
          f"- Total samples: **{len(samples)}**",
          f"- Vulnerable: {results['overall']['total_vulnerable']} | Secure: {results['overall']['total_secure']}",
          f"- **Overall recall: {results['overall']['recall']}** (target ≥ 0.85)",
          f"- Overall precision: {results['overall']['precision']}",
          f"- Overall F1: {results['overall']['f1']}", ""]
    if errors:
        md.append(f"⚠️ {len(errors)} samples raised errors during scanning.")
    md.append("## Per-type")
    md.append("")
    md.append("| Type | TP | FN | FP | TN | Precision | Recall | F1 |")
    md.append("|------|----|----|----|----|----------|-------|----|")
    for t in sorted(results["per_type"]):
        d = results["per_type"][t]
        md.append(f"| {t} | {d['TP']} | {d['FN']} | {d['FP']} | {d['TN']} | {d['precision']} | {d['recall']} | {d['f1']} |")
    md.append("")
    if errors:
        md.append("### Scan errors")
        for e in errors[:20]:
            md.append(f"- `{e['id']}`: {e['error']}")
        md.append("")

    md_path = os.path.join(HERE, "benchmark_results.md")
    with open(md_path, "w", encoding="utf-8") as f:
        f.write("\n".join(md))

    # Console summary
    print("Benchmark complete.")
    print(f"  Samples: {len(samples)} | Errors: {len(errors)}")
    print(f"  Overall recall: {results['overall']['recall']} (target >= 0.85)")
    print(f"  Overall precision: {results['overall']['precision']}")
    for t in sorted(results["per_type"]):
        d = results["per_type"][t]
        print(f"  {t:20s} recall={d['recall']} prec={d['precision']} (TP={d['TP']} FN={d['FN']} FP={d['FP']})")
    print(f"  Wrote {json_path}")
    print(f"  Wrote {md_path}")


if __name__ == "__main__":
    main()
