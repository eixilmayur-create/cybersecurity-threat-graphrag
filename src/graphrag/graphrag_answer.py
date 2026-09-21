# ============================================================
# STAGE 14
# FULL GRAPH-RAG ANSWER GENERATION
# ============================================================
#
# PURPOSE
# -------
# This script completes the Graph-RAG pipeline.
#
# Workflow:
#
# User Question
#      ↓
# Load Retrieved Graph Context
#      ↓
# Build Grounded Prompt
#      ↓
# Gemini
#      ↓
# Structured Answer
#      ↓
# Save Complete Trace
#
#
# IMPORTANT DESIGN RULE
# ---------------------
# Gemini must answer only from the retrieved Knowledge Graph
# context.
#
# If evidence is missing, the answer should explicitly say so.
#
# ============================================================


# pyright: reportUnknownMemberType=false
# pyright: reportUnknownArgumentType=false
# pyright: reportUnknownVariableType=false

from pathlib import Path
import sys
import json
from datetime import datetime, timezone

from google.genai import types

from pydantic import BaseModel, Field


# ============================================================
# 1. PROJECT PATHS
# ============================================================

PROJECT_ROOT = (
    Path(__file__)
    .resolve()
    .parent
    .parent
    .parent
)


CONTEXT_FILE = (
    PROJECT_ROOT
    / "outputs"
    / "graphrag"
    / "retrieved_graph_context.json"
)


OUTPUT_DIR = (
    PROJECT_ROOT
    / "outputs"
    / "graphrag"
)


OUTPUT_DIR.mkdir(
    parents=True,
    exist_ok=True,
)


ANSWER_FILE = (
    OUTPUT_DIR
    / "graphrag_answer.json"
)


TRACE_FILE = (
    OUTPUT_DIR
    / "graphrag_trace.json"
)


# ============================================================
# 2. LOAD ENVIRONMENT
# ============================================================

# Direct script execution puts src/graphrag on sys.path, not src.
sys.path.insert(0, str(PROJECT_ROOT / "src"))
from gemini_config import MODEL_NAME, create_client, describe_error


# ============================================================
# 4. STRUCTURED OUTPUT SCHEMA
# ============================================================

class GraphRAGAnswer(BaseModel):

    answer: str = Field(
        description=(
            "Concise answer grounded only in the supplied graph context."
        )
    )

    evidence: list[str] = Field(
        description=(
            "Short supporting facts taken only from the supplied graph context."
        )
    )

    entities_used: list[str] = Field(
        description=(
            "Entities from the graph context that were used in the answer."
        )
    )

    confidence: float = Field(
        ge=0.0,
        le=1.0,
        description=(
            "Confidence based on completeness of the supplied graph evidence."
        )
    )

    evidence_status: str = Field(
        description=(
            "Use one of: SUFFICIENT, PARTIAL, INSUFFICIENT."
        )
    )


# ============================================================
# 5. CREATE GEMINI CLIENT
# ============================================================

client = create_client()


# ============================================================
# 6. LOAD RETRIEVED GRAPH CONTEXT
# ============================================================

with open(
    CONTEXT_FILE,
    "r",
    encoding="utf-8",
) as file:

    context_package = json.load(
        file
    )


question = (
    context_package[
        "question"
    ]
)


status = (
    context_package[
        "status"
    ]
)


detected_entity = (
    context_package[
        "detected_entity"
    ]
)


graph_context = (
    context_package[
        "graph_context"
    ]
)


print("=" * 80)
print("FULL GRAPH-RAG ANSWER GENERATION")
print("=" * 80)


print(
    f"\nQuestion:\n{question}"
)


print(
    f"\nRetrieval Status: "
    f"{status}"
)


# ============================================================
# 7. HANDLE RETRIEVAL FAILURE
# ============================================================
#
# If no entity or no graph context was found, we do not
# call Gemini unnecessarily.
#
# ============================================================

if (
    status != "SUCCESS"
    or detected_entity is None
    or not graph_context
):

    fallback_result: dict[str, object] = {
        "answer": (
            "The Knowledge Graph does not contain enough "
            "retrieved evidence to answer this question."
        ),
        "evidence": [],
        "entities_used": [],
        "confidence": 0.0,
        "evidence_status": "INSUFFICIENT",
    }


    with open(
        ANSWER_FILE,
        "w",
        encoding="utf-8",
    ) as file:

        json.dump(
            fallback_result,
            file,
            indent=2,
        )


    print(
        "\nNo usable graph context was found."
    )


    print(
        "\nFallback answer saved."
    )


    raise SystemExit(0)


# ============================================================
# 8. BUILD GROUNDED CONTEXT
# ============================================================

context_json = json.dumps(
    graph_context,
    indent=2,
)


entity_json = json.dumps(
    detected_entity,
    indent=2,
)


# ============================================================
# 9. BUILD STRICT GROUNDED PROMPT
# ============================================================

prompt = f"""
You are a Graph-RAG reasoning assistant for a cybersecurity
Knowledge Graph.

Your job is to answer the user's question using ONLY the
retrieved graph evidence supplied below.

STRICT RULES:

1. Use only the supplied graph context.
2. Do not use external cybersecurity knowledge.
3. Do not invent entities, relationships, dates, attacks,
   vulnerabilities, infrastructure, or organizations.
4. If the evidence is incomplete, clearly say that the graph
   provides only partial evidence.
5. If the answer cannot be supported, set evidence_status to
   INSUFFICIENT.
6. Keep the answer concise and factual.
7. Mention relationship paths when helpful.
8. Evidence entries must be direct facts from the supplied
   context.
9. Do not treat similarity, implication, or association as
   stronger than what the graph explicitly represents.
10. Confidence should reflect evidence completeness, not
    general model confidence.

USER QUESTION:
{question}

DETECTED CANONICAL ENTITY:
{entity_json}

RETRIEVED GRAPH CONTEXT:
{context_json}
"""


# ============================================================
# 10. CALL GEMINI
# ============================================================

answer: GraphRAGAnswer
generation_error = None

try:

    response = client.models.generate_content(

        model=MODEL_NAME,

        contents=prompt,

        config=types.GenerateContentConfig(

            response_mime_type="application/json",

            response_schema=GraphRAGAnswer,

            temperature=0.0,
        ),
    )


    # ========================================================
    # IMPORTANT
    # ========================================================
    #
    # Because we supplied a Pydantic model as response_schema,
    # the Google GenAI SDK can parse the structured response
    # automatically.
    #
    # Prefer response.parsed instead of manually parsing
    # response.text again.
    #
    # ========================================================

    if response.parsed is not None:

        answer = GraphRAGAnswer.model_validate(
            response.parsed
        )

    else:

        # Fallback only if parsed response is unavailable.
        #
        # This keeps compatibility with SDK versions where
        # response.parsed may not be populated.

        if not response.text:

            raise ValueError(
                "Gemini returned no parsed object "
                "and no response text."
            )

        answer = GraphRAGAnswer.model_validate_json(
            response.text
        )


except Exception as error:

    generation_error = describe_error(error)

    print("\n" + "!" * 80)
    print("GEMINI GRAPH-RAG ERROR")

    print(
        f"\nError Type: "
        f"{type(error).__name__}"
    )

    print(
        f"\nFull Error:\n"
        f"{generation_error}"
    )

    print("!" * 80)


    answer = GraphRAGAnswer(

        answer=(
            "The graph context was retrieved successfully, "
            "but answer generation failed. Review the "
            "retrieved graph evidence manually."
        ),

        evidence=[],

        entities_used=[],

        confidence=0.0,

        evidence_status="PARTIAL",
    )

# ============================================================
# 11. DISPLAY ANSWER
# ============================================================

print("\n")
print("=" * 80)
print("GRAPH-RAG ANSWER")
print("=" * 80)


print(
    f"\nAnswer:\n"
    f"{answer.answer}"
)


print(
    "\nEvidence:"
)


for item in answer.evidence:

    print(
        f"  - {item}"
    )


print(
    "\nEntities Used:"
)


for entity in answer.entities_used:

    print(
        f"  - {entity}"
    )


print(
    f"\nEvidence Status: "
    f"{answer.evidence_status}"
)


print(
    f"Confidence: "
    f"{answer.confidence}"
)


# ============================================================
# 12. SAVE ANSWER
# ============================================================

answer_payload: dict[str, object] = {
    "generation_status": "FAILED" if generation_error else "SUCCESS",

    "question":
        question,

    "detected_entity":
        detected_entity,

    "answer":
        answer.answer,

    "evidence":
        answer.evidence,

    "entities_used":
        answer.entities_used,

    "confidence":
        answer.confidence,

    "evidence_status":
        answer.evidence_status,
}


with open(
    ANSWER_FILE,
    "w",
    encoding="utf-8",
) as file:

    json.dump(
        answer_payload,
        file,
        indent=2,
    )


# ============================================================
# 13. SAVE FULL TRACE
# ============================================================
#
# Traceability is important in Graph-RAG.
#
# We preserve:
#
# Question
# Detected entity
# Retrieved facts
# Model used
# Final answer
#
# This helps with:
#
# debugging
# evaluation
# audits
# regression testing
#
# ============================================================

trace_payload: dict[str, object] = {

    "timestamp_utc":
        datetime.now(
            timezone.utc
        ).isoformat(),

    "model":
        MODEL_NAME,

    "generation_status": "FAILED" if generation_error else "SUCCESS",

    "generation_error": generation_error,

    "question":
        question,

    "retrieval_status":
        status,

    "detected_entity":
        detected_entity,

    "retrieved_graph_context":
        graph_context,

    "generated_answer":
        answer_payload,
}


with open(
    TRACE_FILE,
    "w",
    encoding="utf-8",
) as file:

    json.dump(
        trace_payload,
        file,
        indent=2,
    )


# ============================================================
# 14. FINAL MESSAGE
# ============================================================

print("\n")
print("=" * 80)
print("GRAPH-RAG GENERATION FAILED" if generation_error else "GRAPH-RAG PIPELINE COMPLETED")
print("=" * 80)


print(
    f"\nAnswer saved to:\n"
    f"{ANSWER_FILE}"
)


print(
    f"\nTrace saved to:\n"
    f"{TRACE_FILE}"
)

if generation_error:
    raise SystemExit(1)
