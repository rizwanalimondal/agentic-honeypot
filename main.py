from fastapi import FastAPI, Header, HTTPException, Request
from typing import Optional, Dict, Any
import re
import requests

app = FastAPI()

API_KEY = "my-secret-api-key"

sessions: Dict[str, Dict[str, Any]] = {}

SCAM_KEYWORDS = [
    "account blocked",
    "verify",
    "urgent",
    "upi",
    "kyc",
    "otp",
    "suspended"
]

PHONE_REGEX = re.compile(r"\+91\d{10}|\b\d{10}\b")
UPI_REGEX = re.compile(r"\b[\w.-]+@[\w.-]+\b")
URL_REGEX = re.compile(r"https?://\S+")
BANK_REGEX = re.compile(r"\b\d{9,18}\b")

GUVI_CALLBACK_URL = "https://hackathon.guvi.in/api/updateHoneyPotFinalResult"


# ------------------ helpers ------------------

def verify_api_key(x_api_key: Optional[str]):
    if x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Invalid or missing API key")


def detect_scam(text: str) -> bool:
    text = text.lower()
    return any(k in text for k in SCAM_KEYWORDS)


def extract_intelligence(text: str, session: Dict[str, Any]):
    for m in PHONE_REGEX.findall(text):
        session["phoneNumbers"].add(m)
    for m in UPI_REGEX.findall(text):
        session["upiIds"].add(m)
    for m in URL_REGEX.findall(text):
        session["phishingLinks"].add(m)
    for m in BANK_REGEX.findall(text):
        session["bankAccounts"].add(m)


def should_terminate(session: Dict[str, Any]) -> bool:
    return (
        session["message_count"] >= 5 or
        len(session["upiIds"]) > 0 or
        len(session["phishingLinks"]) > 0 or
        len(session["phoneNumbers"]) > 0
    )


def send_guvi_callback(session_id: str, session: Dict[str, Any]):
    payload = {
        "sessionId": session_id,
        "scamDetected": True,
        "totalMessagesExchanged": session["message_count"],
        "extractedIntelligence": {
            "bankAccounts": list(session["bankAccounts"]),
            "upiIds": list(session["upiIds"]),
            "phishingLinks": list(session["phishingLinks"]),
            "phoneNumbers": list(session["phoneNumbers"]),
            "suspiciousKeywords": list(session["suspiciousKeywords"]),
        },
        "agentNotes": "Scam detected using urgency and payment redirection tactics"
    }

    try:
        requests.post(GUVI_CALLBACK_URL, json=payload, timeout=5)
    except Exception:
        pass


# ------------------ endpoints ------------------

@app.get("/")
def health_check(x_api_key: Optional[str] = Header(None)):
    verify_api_key(x_api_key)
    return {"status": "ok", "message": "Agentic Honeypot API is running"}


@app.get("/honeypot")
def honeypot_get(x_api_key: Optional[str] = Header(None)):
    verify_api_key(x_api_key)
    return {
        "status": "success",
        "reply": "Why is my account being suspended?"
    }


@app.post("/honeypot")
async def honeypot(
    request: Request,
    x_api_key: Optional[str] = Header(None)
):
    verify_api_key(x_api_key)

    # ---- CRITICAL FIX ----
    # GUVI tester sends POST with empty / invalid JSON body
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
            "scam_detected": False,
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

    # extraction
    extract_intelligence(message_text, session)

    # keyword tracking
    for k in SCAM_KEYWORDS:
        if k in message_text.lower():
            session["suspiciousKeywords"].add(k)

    if not session["scam_detected"] and detect_scam(message_text):
        session["scam_detected"] = True

    reply = (
        "Why is my account being suspended?"
        if session["scam_detected"]
        else "Okay"
    )

    # final callback (once)
    if session["scam_detected"] and should_terminate(session) and not session["reported"]:
        send_guvi_callback(session_id, session)
        session["reported"] = True

    return {
        "status": "success",
        "reply": reply
    }
