"""REST API - drop the firewall in front of any agent or LLM app.

    uvicorn api:app --port 8000
    POST /scan        {"content": "...", "source_type": "web_page", "session_id": "optional"}
    POST /scan/file   multipart file upload (type auto-detected)
    POST /tool/check  {"tool": "send_email", "args": {...}, "user_request": "...", "untrusted_content": "..."}
    POST /feedback    {"text": "...", "is_attack": true}
    GET  /health
"""
from fastapi import FastAPI, File, Form, UploadFile
from pydantic import BaseModel

from firewall import Firewall, llm_judge, toolguard

app = FastAPI(title="Prompt Injection Firewall", version="1.0")
fw = Firewall()


class ScanReq(BaseModel):
    content: str
    source_type: str = "user_message"
    session_id: str | None = None


class ToolReq(BaseModel):
    tool: str
    args: dict
    user_request: str
    untrusted_content: str = ""


class FeedbackReq(BaseModel):
    text: str
    is_attack: bool
    note: str = ""


@app.get("/health")
def health():
    return {"status": "ok", "llm_judge": llm_judge.available() or "offline"}


@app.post("/scan")
def scan(req: ScanReq):
    return fw.scan(req.content, req.source_type, session_id=req.session_id).to_dict()


@app.post("/scan/file")
async def scan_file(file: UploadFile = File(...), session_id: str | None = Form(None)):
    return fw.scan_file(await file.read(), file.filename, session_id=session_id).to_dict()


@app.post("/tool/check")
def tool_check(req: ToolReq):
    taint = toolguard.TaintStore()
    taint.add_from(req.untrusted_content)
    d = toolguard.check(req.tool, req.args, req.user_request, taint)
    return d.__dict__


@app.post("/feedback")
def feedback(req: FeedbackReq):
    fw.feedback(req.text, req.is_attack, req.note)
    return {"status": "recorded"}
