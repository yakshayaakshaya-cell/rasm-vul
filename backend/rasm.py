"""RASM-Vul core: multi-view knowledge base, WRRF retrieval, LLM detection.

Views (channels): code, ast, knowledge, line_change, ast_change.
Embeddings: TF-IDF by default (no GPU, no download). To use UniXCoder instead,
replace the TfidfVectorizer objects with an encoder that returns 768-d vectors.
"""
import difflib, json, os, re, time
from pathlib import Path

import joblib
import numpy as np
import requests
from sklearn.feature_extraction.text import TfidfVectorizer

BASE = Path(__file__).resolve().parent
CONFIG = json.loads((BASE / "config.json").read_text())
CHANNELS = ["code", "ast", "knowledge", "line_change", "ast_change"]

C_KEYWORDS = set(
    "if else for while do switch case default break continue return goto sizeof struct union "
    "enum typedef static const unsigned signed int char long short float double void extern "
    "inline volatile register NULL".split()
)
CWE_NAMES = {
    "CWE-20": "improper input validation", "CWE-22": "path traversal", "CWE-119": "buffer overflow memory bounds",
    "CWE-125": "out-of-bounds read", "CWE-787": "out-of-bounds write", "CWE-190": "integer overflow",
    "CWE-189": "numeric errors", "CWE-200": "information exposure", "CWE-264": "permissions privileges",
    "CWE-310": "cryptographic issues", "CWE-362": "race condition concurrency lock", "CWE-369": "divide by zero",
    "CWE-399": "resource management", "CWE-401": "memory leak", "CWE-416": "use after free",
    "CWE-476": "null pointer dereference", "CWE-617": "reachable assertion", "CWE-703": "improper error handling",
    "CWE-772": "resource leak", "CWE-835": "infinite loop", "CWE-415": "double free", "CWE-908": "uninitialized memory",
}


# ---------- code views ----------
def strip_comments(code: str) -> str:
    return re.sub(r"//[^\n]*|/\*.*?\*/", " ", code, flags=re.S)


def ast_skeleton(code: str) -> str:
    """Lightweight structural view: keywords/operators kept, names -> ID, calls -> CALL.
    (Swap for tree-sitter node sequences if you want a real AST.)"""
    code = re.sub(r'"(\\.|[^"\\])*"', "STR", strip_comments(code))
    toks = re.findall(r"[A-Za-z_]\w*|\d+|==|!=|<=|>=|&&|\|\||->|\+\+|--|<<|>>|[{}()\[\];,*&!<>=+\-/%|^?:.]", code)
    out = []
    for i, t in enumerate(toks):
        if t[0].isalpha() or t[0] == "_":
            if t in C_KEYWORDS:
                out.append(t)
            else:
                out.append("CALL" if i + 1 < len(toks) and toks[i + 1] == "(" else "ID")
        elif t[0].isdigit():
            out.append("NUM")
        else:
            out.append(t)
    return " ".join(out)


def norm_lines(code: str):
    return [l.strip() for l in strip_comments(code).splitlines() if l.strip()]


def line_diff(vul: str, fixed: str):
    a, b = norm_lines(vul), norm_lines(fixed)
    removed, added = [], []
    for tag, i1, i2, j1, j2 in difflib.SequenceMatcher(None, a, b, autojunk=False).get_opcodes():
        if tag in ("replace", "delete"):
            removed += a[i1:i2]
        if tag in ("replace", "insert"):
            added += b[j1:j2]
    return removed, added


def ast_diff(vul: str, fixed: str) -> str:
    a, b = ast_skeleton(vul).split(), ast_skeleton(fixed).split()
    parts = []
    for tag, i1, i2, j1, j2 in difflib.SequenceMatcher(None, a, b, autojunk=False).get_opcodes():
        if tag != "equal":
            parts.append("DEL " + " ".join(a[i1:i2][:40]) + " INS " + " ".join(b[j1:j2][:40]))
    return " ; ".join(parts)


def make_vectorizers():
    code_tok = r"[A-Za-z_]\w*|\d+|==|!=|<=|>=|&&|\|\||->|[^\s\w]"
    return {
        "code": TfidfVectorizer(token_pattern=code_tok, lowercase=False, ngram_range=(1, 2), sublinear_tf=True, max_features=200000),
        "ast": TfidfVectorizer(token_pattern=r"\S+", lowercase=False, ngram_range=(1, 3), sublinear_tf=True, max_features=100000),
        "knowledge": TfidfVectorizer(stop_words="english", ngram_range=(1, 2), sublinear_tf=True),
        "line_change": TfidfVectorizer(token_pattern=code_tok, lowercase=False, ngram_range=(1, 2), sublinear_tf=True, max_features=100000),
        "ast_change": TfidfVectorizer(token_pattern=r"\S+", lowercase=False, ngram_range=(1, 2), sublinear_tf=True),
    }


def build_kb(pairs, out_path):
    """pairs: list of dicts {vul, fixed, project, cwe, knowledge_text}. Training data only."""
    records, docs = [], {c: [] for c in CHANNELS}
    for p in pairs:
        removed, added = line_diff(p["vul"], p["fixed"])
        cwe = p.get("cwe") or ""
        know = " ".join([cwe, CWE_NAMES.get(cwe, ""), p.get("knowledge_text", "")]).strip()
        records.append({
            "project": p.get("project", ""), "cwe": cwe,
            "vul_code": p["vul"], "fixed_code": p["fixed"],
            "removed": removed[:30], "added": added[:30], "knowledge": know,
        })
        docs["code"] += [p["vul"], p["fixed"]]
        docs["ast"] += [ast_skeleton(p["vul"]), ast_skeleton(p["fixed"])]
        docs["knowledge"].append(know or "unknown")
        docs["line_change"].append("\n".join(removed + added) or "empty")
        docs["ast_change"].append(ast_diff(p["vul"], p["fixed"]) or "empty")
    vecs, mats = make_vectorizers(), {}
    for c in CHANNELS:
        mats[c] = vecs[c].fit_transform(docs[c])
        print(f"  {c:12s} matrix {mats[c].shape}")
    joblib.dump({"records": records, "vec": vecs, "mat": mats}, out_path, compress=3)
    print(f"Saved KB with {len(records)} pairs -> {out_path}")


# ---------- LLM ----------
def llm_available() -> bool:
    return bool(os.getenv("LLM_API_KEY"))


def llm_chat(system: str, user: str):
    if not llm_available():
        return None
    base = os.getenv("LLM_BASE_URL", "https://api.deepseek.com").rstrip("/")
    c = CONFIG["llm"]
    try:
        r = requests.post(
            f"{base}/chat/completions",
            headers={"Authorization": "Bearer " + os.environ["LLM_API_KEY"]},
            json={"model": os.getenv("LLM_MODEL", "deepseek-chat"), "temperature": c["temperature"],
                  "top_p": c["top_p"], "max_tokens": c["max_tokens"],
                  "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}]},
            timeout=c["timeout_s"],
        )
        r.raise_for_status()
        return r.json()["choices"][0]["message"]["content"]
    except Exception as e:  # network/quota/etc: fall back gracefully
        print("LLM call failed:", e)
        return None


def parse_json(text):
    if not text:
        return None
    m = re.search(r"\{.*\}", text, flags=re.S)
    try:
        return json.loads(m.group(0)) if m else None
    except json.JSONDecodeError:
        return None


FEATURE_SYS = "You are a vulnerability detection expert and code analysis specialist."
FEATURE_PROMPT = """Analyze the following C/C++ function and decide whether any vulnerability is due to a statement-level issue or a structure-level issue.
Rules:
1. If caused by specific lines (e.g. missing check) set problem_type to "statement" and list exact lines in problem_statements.
2. If caused by architectural/control-flow issues (locking, cleanup paths, ordering) set problem_type to "structure" and list the relevant lines too.
3. Do not invent lines that are not in the code.
4. In "analysis" summarize behavior, solution, purpose and function in 2-3 sentences.
Return JSON only: {{"problem_type": "statement"|"structure", "problem_statements": ["..."], "analysis": "..."}}

Code:
{code}"""
RERANK_PROMPT = """Rank these historical vulnerability cases by relevance to the target function.
Target:
{code}

Candidates:
{cands}

Return JSON only: {{"order": [candidate numbers, most relevant first]}}"""
DETECT_SYS = "You are a vulnerability detector and code expert."
DETECT_PROMPT = """Determine whether the code is the VULNERABLE version or the FIXED version of a function.
1. Analyze the code for missing checks, unsafe memory operations, or exploitable logic.
2. Use the retrieved cases only if relevant; ignore them otherwise. A retrieved case shows lines removed by the fix (vulnerable) and lines added (fix).
3. Fixed code contains proper bounds/null/lock handling or removes the unsafe behavior.
Return JSON only: {{"is_vul": true|false, "cwe_id": "CWE-ID", "vul_desc": "brief description of the flaw or the fix"}}

Code:
{code}

Code analysis: {analysis}

Retrieved cases:
{evidence}"""

RISKY = re.compile(r"\b(memcpy|memmove|strcpy|strcat|sprintf|malloc|calloc|realloc|free|alloca|lock|unlock|mutex)\b|\[[^\]]*\]|->|\bgoto\b")


def heuristic_features(code: str):
    lines = [l.strip() for l in strip_comments(code).splitlines() if RISKY.search(l)]
    ptype = "structure" if re.search(r"\b(\w*lock\w*|mutex|goto)\b", code) else "statement"
    return {"problem_type": ptype, "problem_statements": lines[:6], "analysis": ""}


class Engine:
    def __init__(self, kb_path=None):
        path = Path(kb_path or os.getenv("KB_PATH") or CONFIG["kb_path"])
        if not path.is_absolute():
            path = (BASE / path).resolve()
        self.kb = joblib.load(path)
        self.n = len(self.kb["records"])

    def info(self):
        return {"kb_pairs": self.n, "llm_configured": llm_available(),
                "llm_model": os.getenv("LLM_MODEL", "deepseek-chat") if llm_available() else None}

    def _sims(self, ch, q):
        if not q.strip():
            return None
        qv = self.kb["vec"][ch].transform([q])
        sims = (self.kb["mat"][ch] @ qv.T).toarray().ravel()
        if sims.max() <= 0:
            return None
        if ch in ("code", "ast"):          # two docs per pair (vul, fixed) -> best per pair
            ps = np.zeros(self.n)
            np.maximum.at(ps, np.arange(len(sims)) // 2, sims)
            return ps, sims
        return sims, sims

    @staticmethod
    def wrrf(ranked, weights, k):
        scores = {}
        for ch, order in ranked.items():
            for r, pid in enumerate(order, start=1):
                scores[pid] = scores.get(pid, 0.0) + weights.get(ch, 0.0) / (k + r)
        return scores

    def code_features(self, code):
        data = parse_json(llm_chat(FEATURE_SYS, FEATURE_PROMPT.format(code=code)))
        if data and data.get("problem_type") in ("statement", "structure"):
            data["problem_statements"] = [str(s) for s in data.get("problem_statements", [])][:8]
            data["analysis"] = str(data.get("analysis", ""))
            return data, "llm"
        return heuristic_features(code), "heuristic"

    def _evidence_text(self, pids):
        out = []
        for i, pid in enumerate(pids, 1):
            r = self.kb["records"][pid]
            out.append(f"[{i}] {r['cwe']} ({r['project']})\n  Vulnerable lines removed by fix: {r['removed'][:6]}\n  Lines added by fix: {r['added'][:6]}")
        return "\n".join(out)

    def analyze(self, code: str):
        t0 = time.time()
        code = code.strip()[: CONFIG["max_code_chars"]]
        cfg = CONFIG
        feats, feat_src = self.code_features(code)
        ptype = feats["problem_type"]
        weights = cfg["weights"][ptype]
        lines = "\n".join(feats["problem_statements"])
        queries = {"code": code, "ast": ast_skeleton(code), "knowledge": feats["analysis"] or code,
                   "line_change": lines, "ast_change": ast_skeleton(lines)}

        ranked, ps_by_ch, code_doc_sims = {}, {}, None
        for ch, q in queries.items():
            res = self._sims(ch, q)
            if res is None:
                continue
            ps, sims = res
            order = [int(i) for i in np.argsort(-ps)[: cfg["top_n_channel"]] if ps[i] > 0]
            ranked[ch], ps_by_ch[ch] = order, ps
            if ch == "code":
                code_doc_sims = sims
        fused = self.wrrf(ranked, weights, cfg["k_rrf"])
        if not fused:
            raise ValueError("No similar cases found in the knowledge base.")
        cand = sorted(fused, key=fused.get, reverse=True)[: cfg["rerank_candidates"]]

        # LLM re-rank
        top = cand[: cfg["top_k"]]
        if cfg["use_llm_rerank"] and llm_available():
            txt = "\n".join(f"{i}. {self.kb['records'][p]['cwe']} removed={self.kb['records'][p]['removed'][:3]} added={self.kb['records'][p]['added'][:3]}" for i, p in enumerate(cand, 1))
            data = parse_json(llm_chat(DETECT_SYS, RERANK_PROMPT.format(code=code, cands=txt)))
            if data and isinstance(data.get("order"), list):
                idx = [int(i) - 1 for i in data["order"] if str(i).isdigit() and 0 < int(i) <= len(cand)]
                idx += [i for i in range(len(cand)) if i not in idx]
                top = [cand[i] for i in idx][: cfg["top_k"]]

        conf = float(ps_by_ch.get("code", np.zeros(self.n))[top[0]])
        # ---- decision ----
        mode, verdict = "retrieval-only", None
        data = parse_json(llm_chat(DETECT_SYS, DETECT_PROMPT.format(
            code=code, analysis=feats["analysis"] or "n/a", evidence=self._evidence_text(top[:3]))))
        if data and "is_vul" in data:
            mode = "llm"
            is_vul = str(data["is_vul"]).lower() == "true"
            verdict = {"is_vul": is_vul, "cwe_id": data.get("cwe_id") or self.kb["records"][top[0]]["cwe"],
                       "vul_desc": str(data.get("vul_desc", ""))}
        if verdict is None:  # nearest-neighbour vote over the most similar historical functions
            near = np.argsort(-code_doc_sims)[:5] if code_doc_sims is not None else []
            vote = sum(code_doc_sims[d] * (1 if d % 2 == 0 else -1) for d in near)
            is_vul = bool(vote > 0)
            verdict = {"is_vul": is_vul, "cwe_id": self.kb["records"][top[0]]["cwe"] or "unknown",
                       "vul_desc": "Retrieval-only estimate: the most similar historical functions were mostly "
                                   + ("vulnerable versions." if is_vul else "fixed versions.")
                                   + " Set LLM_API_KEY to enable full reasoning."}

        evidence = []
        for pid in top:
            r = self.kb["records"][pid]
            evidence.append({
                "pair_id": pid, "project": r["project"], "cwe": r["cwe"],
                "fused_score": round(fused.get(pid, 0.0), 5),
                "channel_ranks": {ch: (ranked[ch].index(pid) + 1 if pid in ranked[ch] else None) for ch in ranked},
                "removed": r["removed"][:10], "added": r["added"][:10],
                "vul_code": r["vul_code"][:2500], "fixed_code": r["fixed_code"][:2500],
            })
        return {
            **verdict, "verdict": "vulnerable" if verdict["is_vul"] else "fixed", "mode": mode,
            "feature_source": feat_src, "problem_type": ptype,
            "suspicious_lines": feats["problem_statements"], "analysis": feats["analysis"],
            "weights": weights, "retrieval_confidence": round(conf, 4),
            "doubtful": conf < cfg["similarity_threshold"],
            "evidence": evidence, "latency_ms": int((time.time() - t0) * 1000),
        }
