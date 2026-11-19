# Automated API Security Scanner

A Streamlit-based authorized testing tool for focused REST and GraphQL checks:
- BOLA comparison using two authorized test identities and a tester-supplied object ID.
- Low-volume sequential rate-limit check (maximum 20 requests; stops on HTTP 429).

## Run locally

```bash
python -m venv .venv
# Windows PowerShell
.venv\Scripts\Activate.ps1
# macOS/Linux
source .venv/bin/activate
pip install -r requirements.txt
streamlit run app.py
```

Use only APIs you own or have explicit written permission to test. Prefer staging, synthetic records, and dedicated test accounts. The scanner does not discover routes, enumerate IDs, bypass rate limits, or perform destructive tests.

This is a prototype testing harness, not a complete DAST product. Findings require manual validation.
