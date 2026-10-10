# Prompt Injection Firewall

A layered, multimodal firewall that stops direct and indirect prompt injection before it reaches an AI agent, and stops hijacked tool calls before they run. It is free and runs offline. **Self-assessed position: D3 / F3.** See `ARCHITECTURE.md` for the full design and justification.

## Setup (about 5 minutes)

```bash
# Python 3.10+. Tesseract is needed for image OCR:
#   Ubuntu: sudo apt install tesseract-ocr     macOS: brew install tesseract
#   Windows: install from https://github.com/UB-Mannheim/tesseract/wiki and add it to PATH
pip install -r requirements.txt
python -c "from firewall import ml; ml.build()"   # trains the classifier (a few seconds)
python -m agent.scenarios                         # writes the demo files to demo_inputs/
```

Optional free LLM judge (use only one):

```bash
export GROQ_API_KEY=...      # free key from console.groq.com
export GEMINI_API_KEY=...    # free key from aistudio.google.com
export OLLAMA_HOST=http://localhost:11434   # local, after: ollama pull llama3.1
```

## Run

```bash
streamlit run app.py                 # dashboard: the working demo
uvicorn api:app --port 8000          # REST API for integrating with any agent
python -m evaluation.evaluate        # regenerates evaluation/REPORT.md
python -m pytest -q tests            # 7 tests
```

## Demo script (about 5 minutes)

1. **Agent demo tab.** Choose *Poisoned web page* and click **Run both assistants**.
   - Left: the unprotected assistant emails the inbox to the attacker and praises the hotel.
   - Right: the protected assistant gives a clean summary, with the hidden div shown as evidence.
2. Repeat with *Invoice email* (white-text HTML transfers money), *Resume PDF* (invisible text leaks the system prompt), *Agenda image* (faint text, caught by OCR contrast reveal) and *Code file*. In the code file, the comment block is stripped and the code is kept. Even if the attack had slipped through, the tool guard stops `run_shell`.
3. Run *Clean report*. It passes untouched, which shows minimal disruption.
4. **Inspect content tab.** Upload any file and open *What the firewall extracted* to see the hidden channels highlighted, then *What the assistant receives*.
5. **Conversation tab.** Play *Payload split*. Each turn alone looks harmless; the session tracker catches the combination.
6. **Evaluation tab.** Precision, recall and FPR by attack type and by format, plus the claimed grid cell.
7. **Audit log tab.** Every decision is logged. Mark a wrong call in *Inspect content* and click **Retrain now** to show trainability.

## 9-blocker justification

| Axis | Claim | Evidence |
|---|---|---|
| Depth | **D3**: highly heterogeneous multimodal input, high demonstrable reliability | 11 input types, including images, scanned PDFs, email attachments and hidden channels in each format. Reliability is measured on 424 file-rendered samples: precision 98.6%, recall 98.3%, FPR 3.0%; 100% detection of hidden payloads in HTML, Markdown, PDF, DOCX, email, API and code. |
| Features | **F3**: at least 7 attack types (we cover 9) | Each of the 9 types has dedicated detectors and is named in the verdict with evidence. Supporting features include observability, trainability, fault tolerance, an API and human approval. |

Caveats are stated openly in `evaluation/REPORT.md`: the evaluation set is synthetic, and image OCR is the weakest channel (71% on faint hidden text).
