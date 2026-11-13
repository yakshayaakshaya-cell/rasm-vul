"""Build the multi-view knowledge base from PrimeVul *training* pairs only.
Usage: python build_kb.py --train ../data/primevul_train_paired.jsonl --max-pairs 1500
"""
import argparse, json, random
from pathlib import Path
from rasm import build_kb, llm_chat, parse_json

KNOW_PROMPT = """Organize vulnerability knowledge from this vulnerable/fixed pair. Omit specific resource names so it generalizes.
Return JSON only: {{"preconditions": "...", "trigger_condition": "...", "code_behavior": "...", "solution": "..."}}

VULNERABLE:
{vul}

FIXED:
{fixed}"""


def norm_cwe(v):
    if isinstance(v, list):
        v = v[0] if v else ""
    return v or ""


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--train", required=True)
    ap.add_argument("--max-pairs", type=int, default=1500, help="0 = use all pairs")
    ap.add_argument("--out", default="../kb/kb.joblib")
    ap.add_argument("--llm-knowledge", type=int, default=0, help="extract LLM knowledge for the first N pairs (needs LLM_API_KEY)")
    ap.add_argument("--seed", type=int, default=42)
    a = ap.parse_args()

    rows = [json.loads(l) for l in open(a.train, encoding="utf-8")]
    pairs = []
    for i in range(0, len(rows) - 1, 2):          # PrimeVul paired: consecutive vul/fixed rows
        x, y = rows[i], rows[i + 1]
        if x["target"] == y["target"]:
            continue
        v, f = (x, y) if x["target"] == 1 else (y, x)
        know = " ".join(str(v.get(k, "")) for k in ("message", "commit_message", "cve_desc"))[:600]
        pairs.append({"vul": v["func"], "fixed": f["func"], "project": v.get("project", ""),
                      "cwe": norm_cwe(v.get("cwe")), "knowledge_text": know})
    print(f"{len(pairs)} usable pairs")
    random.Random(a.seed).shuffle(pairs)
    if a.max_pairs:
        pairs = pairs[: a.max_pairs]

    for p in pairs[: a.llm_knowledge]:
        d = parse_json(llm_chat("You are a vulnerability detection expert.", KNOW_PROMPT.format(vul=p["vul"][:4000], fixed=p["fixed"][:4000])))
        if d:
            p["knowledge_text"] += " " + " ".join(str(x) for x in d.values())

    out = Path(a.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    build_kb(pairs, out)


if __name__ == "__main__":
    main()
