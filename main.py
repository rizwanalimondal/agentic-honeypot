from fastapi import FastAPI, Header, HTTPException, Body
from typing import Optional, Dict, Any
import re
import requests

app = FastAPI()

API_KEY = "my-secret-api-key"

sessions = {}

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


def verify_api_key(x_api_key: Optional[str] = Header(None)):
    if x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Invalid or missing API key")


def detect_scam(text: str) -> bool:
    text = text.lower()
    return any(keyword in text for keyword in SCAM_KEYWORDS)


def extract_intelligence(text: str, session: Dict[str, Any]):
    for match in PHONE_REGEX.findall(text):
        session["phoneNumbers"].add(match)

    for match in UPI_REGEX.findall(text):
        session["upiIds"].add(match)

    for match in URL_REGEX.findall(text):
        session["phishingLinks"].add(match)

    for match in BANK_REGEX.findall(text):
        session["bankAccounts"].add(match)


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
            "suspiciousKeywords": list(session["suspiciousKeywords"])
        },
        "agentNotes": "Scam detected using urgency and payment redirection tactics"
    }

    try:
        requests.post(GUVI_CALLBACK_URL, json=payload, timeout=5)
    except Exception:
        pass


@app.get("/")
def health_check(x_api_key: Optional[str] = Header(None)):
    verify_api_key(x_api_key)
    return {"status": "ok", "message": "Agentic Honeypot API is running"}


@app.post("/honeypot")
def honeypot(
    payload: Optional[Dict[str, Any]] = Body(None),
    x_api_key: Optional[str] = Header(None)
):
    verify_api_key(x_api_key)

    if payload is None:
        return {
            "status": "success",
            "reply": "Why is my account being suspended?"
        }

    session_id = payload.get("sessionId")
    message_text = payload.get("message", {}).get("text", "")

    bank_accounts = re.findall(r"\b\d{12,18}\b", message_text)

    upi_ids = re.findall(
        r"\b[a-zA-Z0-9.\-_]{2,}@[a-zA-Z]{2,}\b",
        message_text
    )

    phone_numbers = re.findall(
        r"\+91[-\s]?\d{10}\b|\b\d{10}\b",
        message_text
    )

    phishing_links = re.findall(
        r"https?://[^\s]+",
        message_text
    )

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

    sessions[session_id]["bankAccounts"].update(bank_accounts)
    sessions[session_id]["upiIds"].update(upi_ids)
    sessions[session_id]["phoneNumbers"].update(phone_numbers)
    sessions[session_id]["phishingLinks"].update(phishing_links)


    session = sessions[session_id]
    session["message_count"] += 1

    for keyword in SCAM_KEYWORDS:
        if keyword in message_text.lower():
            session["suspiciousKeywords"].add(keyword)

    if not session["scam_detected"] and detect_scam(message_text):
        session["scam_detected"] = True

    if session["scam_detected"]:
        extract_intelligence(message_text, session)
        reply = "Why is my account being suspended?"
    else:
        reply = "Okay"

    # FINAL CALLBACK (only once)
    if session["scam_detected"] and should_terminate(session) and not session["reported"]:
        send_guvi_callback(session_id, session)
        session["reported"] = True

    return {
        "status": "success",
        "reply": reply
    }
