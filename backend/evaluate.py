"""Evaluate on a paired jsonl (validation or test). Never include these rows in the KB.
Usage: python evaluate.py --data ../data/primevul_validation_paired.jsonl --limit 100
"""
import argparse, json
from rasm import Engine


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", required=True)
    ap.add_argument("--limit", type=int, default=100, help="number of pairs")
    a = ap.parse_args()
    rows = [json.loads(l) for l in open(a.data, encoding="utf-8")]
    eng = Engine()
    tp = tn = fp = fn = pair_ok = n = 0
    for i in range(0, min(len(rows) - 1, a.limit * 2), 2):
        x, y = rows[i], rows[i + 1]
        if x["target"] == y["target"]:
            continue
        ok = []
        for r in (x, y):
            pred = eng.analyze(r["func"])["is_vul"]
            t = bool(r["target"])
            tp += pred and t; tn += (not pred) and (not t); fp += pred and (not t); fn += (not pred) and t
            ok.append(pred == t)
        pair_ok += all(ok); n += 1
        if n % 10 == 0:
            print(f"  {n} pairs done")
    tot = tp + tn + fp + fn
    p = tp / (tp + fp) if tp + fp else 0
    r = tp / (tp + fn) if tp + fn else 0
    f1 = 2 * p * r / (p + r) if p + r else 0
    print(json.dumps({"pairs": n, "accuracy": round((tp + tn) / tot, 4), "precision": round(p, 4),
                      "recall": round(r, 4), "f1": round(f1, 4), "pair_accuracy": round(pair_ok / n, 4)}, indent=2))


if __name__ == "__main__":
    main()
