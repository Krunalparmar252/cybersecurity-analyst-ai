"""
Manual live-verification script -- NOT a pytest test.

Renamed from test_reasoning.py: pytest's default test_*.py glob was
collecting this file even though it executes top-level API-calling code
on import and requires a real GROQ_API_KEY. That's always been true (pre-
dates the LangChain swap) -- it just happened to surface now while
re-running the suite. Kept as a manual script for exactly the purpose its
name suggests: run this by hand, with a real key exported, to do the
still-pending live Groq/LangChain verification.

Usage:
    export GROQ_API_KEY=your_key_here
    python manual_verify_reasoning.py
"""

import os
from langchain_groq import ChatGroq
from analyst.detection.engine import CandidateFinding
from analyst.reasoning.engine import MODEL, analyze_finding

client = ChatGroq(model=MODEL, api_key=os.environ["GROQ_API_KEY"], max_tokens=1500)
finding = CandidateFinding("SQLI-001", "SQL Injection", "app.py", 15,
    "query = f\"SELECT ...\"", "high", "static")
source = open("demo_app/app.py", "rb").read()
result = analyze_finding(finding, source, client)
print(result.to_dict())
