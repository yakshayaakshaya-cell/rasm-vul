# RASM-Vul (basic implementation)

Checks whether a C/C++ function is the vulnerable or fixed version, using retrieval over
past vulnerable/fixed pairs (code, syntax, knowledge, line-change, syntax-change views),
WRRF fusion, and an LLM for the final verdict.

## Run locally
    cd backend
    python -m venv .venv && source .venv/bin/activate      # Windows: .venv\Scripts\activate
    pip install -r requirements.txt
    python build_kb.py --train ../data/primevul_train_paired.jsonl --max-pairs 1500
    export LLM_API_KEY=your-key                             # Windows: set LLM_API_KEY=your-key
    uvicorn main:app --reload
Open http://localhost:8000

## Evaluate (use validation/test files, never put them in the KB)
    python evaluate.py --data ../data/primevul_validation_paired.jsonl --limit 100
