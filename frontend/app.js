const $ = (s) => document.querySelector(s);
const NAMES = { code: "Code text", ast: "Syntax structure", knowledge: "Knowledge", line_change: "Line changes", ast_change: "Syntax changes" };
let API = "";
let examples = [];

const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

async function init() {
  try { API = ((await (await fetch("config.json")).json()).apiBase || "").replace(/\/$/, ""); } catch (e) {}
  try {
    examples = await (await fetch("examples.json")).json();
    $("#example").insertAdjacentHTML("beforeend", examples.map((e, i) => `<option value="${i}">${esc(e.label)}</option>`).join(""));
  } catch (e) {}
  try {
    const h = await (await fetch(API + "/api/health")).json();
    $("#status").textContent = `${h.kb_pairs} past cases loaded. ` + (h.llm_configured ? `Language model: ${h.llm_model}` : "No language model key set, using retrieval only");
  } catch (e) {
    $("#status").textContent = "Server not reachable. Check apiBase in config.json.";
    $("#status").classList.add("bad");
  }
}

$("#example").addEventListener("change", (ev) => {
  const e = examples[ev.target.value];
  if (!e) return;
  $("#code").value = e.code;
  $("#expected").textContent = `Dataset label: ${e.expected}`;
  reset();
});
$("#clear").addEventListener("click", () => { $("#code").value = ""; $("#expected").textContent = ""; $("#example").value = ""; reset(); });

function reset() { $("#result").hidden = true; $("#error").hidden = true; $("#empty").hidden = false; }

$("#run").addEventListener("click", async () => {
  const code = $("#code").value.trim();
  if (code.length < 10) return showError("Paste a function with at least a few lines of code.");
  const btn = $("#run");
  btn.disabled = true; btn.textContent = "Analyzing";
  try {
    const r = await fetch(API + "/api/analyze", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ code }) });
    const data = await r.json();
    if (!r.ok) throw new Error(data.detail || "The server could not analyze this code.");
    render(data);
  } catch (e) {
    showError(e.message || "Could not reach the server.");
  } finally {
    btn.disabled = false; btn.textContent = "Analyze function";
  }
});

function showError(msg) {
  $("#empty").hidden = true; $("#result").hidden = true;
  $("#error").hidden = false; $("#error").textContent = msg;
}

function render(d) {
  $("#empty").hidden = true; $("#error").hidden = true;
  const vul = d.is_vul;
  const bars = Object.entries(d.weights).sort((a, b) => b[1] - a[1]).map(([k, w]) =>
    `<span>${NAMES[k]}</span><div class="bar"><i style="width:${w * 100 / 0.4 > 100 ? 100 : w * 100 / 0.4}%"></i></div><span>${Math.round(w * 100)}%</span>`).join("");
  const cases = d.evidence.map((e, i) => `
    <article class="case">
      <header><strong>Case ${i + 1}: ${esc(e.project)}</strong><span>${esc(e.cwe || "CWE unknown")}</span><span>fusion score ${e.fused_score}</span></header>
      <div class="diff">
        <div class="old"><small>Removed by the fix (vulnerable)</small>${esc(e.removed.join("\n")) || "No removed lines"}</div>
        <div class="new"><small>Added by the fix</small>${esc(e.added.join("\n")) || "No added lines"}</div>
      </div>
      <details><summary>Show both full functions</summary>
        <pre>${esc(e.vul_code)}</pre><pre>${esc(e.fixed_code)}</pre></details>
    </article>`).join("");
  $("#result").innerHTML = `
    <div class="verdict ${vul ? "vul" : "fix"}">
      <p class="word">${vul ? "Vulnerable version" : "Fixed version"}</p>
      <p>${esc(d.vul_desc)}</p>
    </div>
    <div class="meta">
      <span class="chip">${esc(d.cwe_id)}</span>
      <span class="chip">Bug type: ${d.problem_type === "statement" ? "single statement" : "structure"}</span>
      <span class="chip">Match strength ${d.retrieval_confidence}</span>
      <span class="chip">${d.mode === "llm" ? "Language model reasoning" : "Retrieval only"}</span>
      <span class="chip">${d.latency_ms} ms</span>
    </div>
    ${d.doubtful ? `<div class="warn">The closest past cases are only weak matches, so treat this result as doubtful.</div>` : ""}
    ${d.mode !== "llm" ? `<div class="warn">No language model answered, so this verdict comes from nearest-neighbor voting and is close to a coin flip on look-alike code. Set LLM_API_KEY on the server.</div>` : ""}
    <div class="block"><h3>How much each view counted</h3><div class="bars">${bars}</div></div>
    ${d.suspicious_lines.length ? `<div class="block"><h3>Lines the system found suspicious</h3><pre class="lines">${esc(d.suspicious_lines.join("\n"))}</pre></div>` : ""}
    <div class="block"><h3>Closest past cases</h3>${cases}</div>`;
  $("#result").hidden = false;
}
init();
