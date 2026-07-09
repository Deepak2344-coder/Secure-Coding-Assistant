import json
import os
import re
from dataclasses import dataclass

from dotenv import load_dotenv

from llm_synthesis.prompts import build_prompt, SYSTEM_PROMPT
from retrieval_layer.retriever import RetrievalResult
from backend.schemas import Issue

load_dotenv()

GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")
GROQ_API_KEY = os.getenv("GROQ_API_KEY", "")

_gemini_client = None
_groq_client = None


def _get_gemini_client():
    global _gemini_client
    if _gemini_client is None and GEMINI_API_KEY:
        from google import genai
        _gemini_client = genai.Client(api_key=GEMINI_API_KEY)
    return _gemini_client


def _get_groq_client():
    global _groq_client
    if _groq_client is None and GROQ_API_KEY:
        from groq import Groq
        _groq_client = Groq(api_key=GROQ_API_KEY)
    return _groq_client


@dataclass
class FixSuggestion:
    explanation: str
    secure_rewrite: str
    cwe_reference: str


def _parse_json(text: str) -> dict | None:
    json_match = re.search(r"\{.*\}", text, re.DOTALL)
    if not json_match:
        return None
    try:
        return json.loads(json_match.group(0))
    except json.JSONDecodeError:
        return None


def _call_gemini(prompt: str) -> str | None:
    client = _get_gemini_client()
    if not client:
        return None
    try:
        response = client.models.generate_content(
            model="gemini-2.0-flash",
            contents=prompt,
            config={
                "system_instruction": SYSTEM_PROMPT,
            },
        )
        return response.text
    except Exception:
        return None


def _call_groq(prompt: str) -> str | None:
    client = _get_groq_client()
    if not client:
        return None
    try:
        response = client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": prompt},
            ],
            temperature=0.3,
        )
        return response.choices[0].message.content
    except Exception:
        return None


def synthesize(issue: Issue, retrieval: RetrievalResult) -> FixSuggestion | None:
    if not GEMINI_API_KEY and not GROQ_API_KEY:
        return None

    prompt = build_prompt(issue.vuln_type.value, issue.snippet, retrieval.retrieved_text)

    raw = _call_gemini(prompt)
    if raw is None:
        raw = _call_groq(prompt)
    if raw is None:
        return None

    data = _parse_json(raw)
    if not data:
        return None

    return FixSuggestion(
        explanation=data.get("explanation", ""),
        secure_rewrite=data.get("secure_rewrite", ""),
        cwe_reference=data.get("cwe_reference", retrieval.cwe_reference),
    )
