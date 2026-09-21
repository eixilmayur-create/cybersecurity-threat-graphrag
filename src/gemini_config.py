"""Shared Gemini configuration and actionable, secret-safe errors."""
import os
from pathlib import Path
from dotenv import load_dotenv
from google import genai
from google.genai import types

load_dotenv(Path(__file__).resolve().parent.parent / ".env", override=True)
MODEL_NAME = os.getenv("GEMINI_MODEL", "gemini-3.5-flash-lite").strip()

def create_client():
    key = os.getenv("GEMINI_API_KEY", "").strip()
    if not key:
        raise ValueError("Set GEMINI_API_KEY in the project .env file.")
    return genai.Client(api_key=key, http_options=types.HttpOptions(timeout=60000))

def describe_error(error):
    message = str(error)
    for name in ("GEMINI_API_KEY", "GOOGLE_API_KEY"):
        secret = os.getenv(name)
        if secret:
            message = message.replace(secret, "[REDACTED]")
    code = getattr(error, "code", None)
    hint = {
        404: "Model unavailable: set GEMINI_MODEL in .env to a model supported by your account, then run src/test_gemini_connection.py.",
        400: "Check the API key and request parameters.",
        403: "Check the API key permissions and project access.",
        429: "Check Gemini API quota/billing; wait before retrying a temporary rate limit.",
        503: "Gemini is temporarily unavailable; retry later.",
    }.get(code, "Check network/proxy settings if this is a connection error; run src/test_gemini_connection.py for diagnosis.")
    return f"{type(error).__name__}: {message} | {hint}"
