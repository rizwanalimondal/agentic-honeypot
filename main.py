from fastapi import FastAPI, Header, HTTPException, Request
from typing import Optional, Dict, Any
import re
import requests

app = FastAPI()

API_KEY = "my-secret-api-key"
sessions: Dict[str, Dict[str, Any]] = {}

SCAM_KEYWORDS = [
    "account blocked", "verify", "urgent", "upi", "kyc", "otp", "suspended"
]

PHONE_REGEX = re.compile(r"\+91\d{10}|\b\d{10}\b")
UPI_REGEX = re.compile(r"\b[\w.-]+@[\w.-]+\b")
URL_REGEX = re.compile(r"https?://\S+")
BANK_REGEX = re.compile(r"\b\d{9,18}\b")

GUVI_CALLBACK_URL = "https://hackathon.guvi.in/api/updateHoneyPotFinalResult"


def verify_api_key(x_api_key: Optional[str]):
    if x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Invalid or missing API key")


@app.get("/")
def health(x_api_key: Optional[str] = Header(None)):
    verify_api_key(x_api_key)
    return {"status": "ok", "message": "Agentic Honeypot API is running"}


# 🔥 ACCEPT EVERYTHING GUVI CAN THROW
@app.api_route(
    "/honeypot",
    methods=["GET", "POST", "HEAD", "OPTIONS"]
)
async def honeypot(request: Request, x_api_key: Optional[str] = Header(None)):
    verify_api_key(x_api_key)

    # Always return valid JSON no matter what
    try:
        payload = await request.json()
    except Exception:
        return {
            "status": "success",
            "reply": "Why is my account being suspended?"
        }

    if not isinstance(payload, dict):
        return {
            "status": "success",
            "reply": "Why is my account being suspended?"
        }

    session_id = payload.get("sessionId")
    message_text = payload.get("message", {}).get("text", "")

    if not session_id or not message_text:
        return {
            "status": "success",
            "reply": "Why is my account being suspended?"
        }

    if session_id not in sessions:
        sessions[session_id] = {
            "message_count": 0,
            "bankAccounts": set(),
            "upiIds": set(),
            "phishingLinks": set(),
            "phoneNumbers": set(),
            "suspiciousKeywords": set(),
            "reported": False
        }

    session = sessions[session_id]
    session["message_count"] += 1

    session["bankAccounts"].update(BANK_REGEX.findall(message_text))
    session["upiIds"].update(UPI_REGEX.findall(message_text))
    session["phishingLinks"].update(URL_REGEX.findall(message_text))
    session["phoneNumbers"].update(PHONE_REGEX.findall(message_text))

    for k in SCAM_KEYWORDS:
        if k in message_text.lower():
            session["suspiciousKeywords"].add(k)

    return {
        "status": "success",
        "reply": "Why is my account being suspended?"
    }
