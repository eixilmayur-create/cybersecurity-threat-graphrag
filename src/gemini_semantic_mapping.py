# ============================================================
# STAGE 11
# GEMINI SEMANTIC MAPPING + CONFIDENCE ROUTING
# ============================================================
#
# PURPOSE
# -------
# Stage 10 gave us Top-K vector candidates.
#
# This stage asks Gemini to evaluate those candidates
# semantically and return one of:
#
#   REUSE
#   NEW_ENTITY
#   UNCERTAIN
#
# Then we combine:
#
#   Vector similarity
#        +
#   Gemini confidence
#
# to produce a final routing decision.
#
# ============================================================


# pyright: reportUnknownMemberType=false
# pyright: reportUnknownArgumentType=false
# pyright: reportUnknownVariableType=false

from gemini_config import MODEL_NAME, create_client, describe_error
from pathlib import Path
from typing import Literal

import pandas as pd

from dotenv import load_dotenv

from google import genai # type: ignore
from google.genai import types

from pydantic import BaseModel, Field


# ============================================================
# 1. PROJECT PATHS
# ============================================================

PROJECT_ROOT = Path(__file__).resolve().parent.parent


INPUT_FILE = (
    PROJECT_ROOT
    / "outputs"
    / "vector_search"
    / "vector_candidate_results.csv"
)


OUTPUT_DIR = (
    PROJECT_ROOT
    / "outputs"
    / "gemini_mapping"
)


OUTPUT_DIR.mkdir(
    parents=True,
    exist_ok=True,
)


OUTPUT_FILE = (
    OUTPUT_DIR
    / "gemini_mapping_results.csv"
)


# ============================================================
# 2. LOAD ENVIRONMENT VARIABLES
# ============================================================

load_dotenv(
    PROJECT_ROOT / ".env",
    override=True,
)


# ============================================================
# 3. GEMINI MODEL
# ============================================================
#
# Use a lightweight text model for semantic classification.
#
# If this model name is unavailable in your account later,
# replace it with another currently supported Gemini text model.
#
# ============================================================

# MODEL_NAME is shared with the connection test via gemini_config.


# ============================================================
# 4. OUTPUT SCHEMA
# ============================================================
#
# We force Gemini to return a controlled decision structure.
#
# ============================================================

class SemanticDecision(BaseModel):

    decision: Literal[
        "REUSE",
        "NEW_ENTITY",
        "UNCERTAIN",
    ] = Field(
        description=(
            "Final semantic mapping decision."
        )
    )

    selected_canonical_id: str | None = Field(
        description=(
            "Canonical entity ID if decision is REUSE. "
            "Otherwise null."
        )
    )

    selected_canonical_name: str | None = Field(
        description=(
            "Canonical entity name if decision is REUSE. "
            "Otherwise null."
        )
    )

    confidence: float = Field(
        ge=0.0,
        le=1.0,
        description=(
            "Confidence between 0 and 1."
        )
    )

    reasoning: str = Field(
        description=(
            "Short explanation based only on supplied candidate data."
        )
    )


# ============================================================
# 5. CREATE GEMINI CLIENT
# ============================================================
#
# The Gemini SDK automatically reads GEMINI_API_KEY.
#
# ============================================================

client = create_client()


# ============================================================
# 6. LOAD VECTOR CANDIDATES

# ============================================================

candidate_df: pd.DataFrame = pd.read_csv(
    INPUT_FILE
)


print("=" * 80)
print("GEMINI SEMANTIC MAPPING")
print("=" * 80)


print(
    f"\nCandidate rows loaded: "
    f"{len(candidate_df)}"
)


# ============================================================
# 7. PROMPT BUILDER
# ============================================================

def build_prompt(
    incoming_name: str,
    entity_type: str,
    candidate_rows: pd.DataFrame,
) -> str:
    """
    Build a controlled prompt for Gemini.

    IMPORTANT:
    Gemini is instructed to evaluate only the provided
    candidates and not invent external facts.
    """

    candidate_text = ""


    for _, row in candidate_rows.iterrows():

        candidate_text += (
            f"\nCandidate Rank: "
            f"{row['candidate_rank']}\n"

            f"Canonical ID: "
            f"{row['canonical_id']}\n"

            f"Canonical Name: "
            f"{row['canonical_name']}\n"

            f"Vector Similarity: "
            f"{row['similarity_score']}\n"

            f"Description: "
            f"{row['canonical_description']}\n"
        )


    prompt = f"""
You are performing semantic entity mapping for a cybersecurity
Knowledge Graph.

Your task is to determine whether the incoming entity should:

REUSE
- when it clearly represents one of the supplied canonical entities.

NEW_ENTITY
- when none of the supplied candidates appear to represent the same entity.

UNCERTAIN
- when there is insufficient evidence to decide safely.

Important rules:

1. Use only the supplied data.
2. Do not invent cybersecurity facts.
3. Do not assume the highest vector similarity is automatically correct.
4. Entity type must be consistent.
5. Prefer UNCERTAIN when evidence is ambiguous.
6. Return REUSE only when there is strong semantic evidence.
7. If REUSE is selected, provide the canonical ID and name.
8. Keep reasoning concise.

Incoming Entity:
Name: {incoming_name}
Entity Type: {entity_type}

Candidate Entities:
{candidate_text}
"""

    return prompt


# ============================================================
# 8. GEMINI SEMANTIC DECISION
# ============================================================

def get_gemini_decision(
    incoming_name: str,
    entity_type: str,
    candidate_rows: pd.DataFrame,
) -> SemanticDecision:

    prompt = build_prompt(
        incoming_name,
        entity_type,
        candidate_rows,
    )


    try:

        response = (
            client.models.generate_content(

                model=MODEL_NAME,

                contents=prompt,

                config=types.GenerateContentConfig(

                    response_mime_type=(
                        "application/json"
                    ),

                    response_schema=(
                        SemanticDecision
                    ),

                    temperature=0.0,
                ),
            )
        )


        response_text = response.text
        if response_text is None:
            raise ValueError(
                "Gemini returned an empty response body."
            )

        decision = (
            SemanticDecision
            .model_validate_json(
                response_text
            )
        )


        return decision


    except Exception as error:

        print(
            f"\nGemini error for "
            f"{incoming_name}: "
            f"{describe_error(error)}"
        )


        # If Gemini fails, do NOT silently auto-merge.
        #
        # Route it conservatively to UNCERTAIN.

        return SemanticDecision(
            decision="UNCERTAIN",
            selected_canonical_id=None,
            selected_canonical_name=None,
            confidence=0.0,
            reasoning=(
                "Gemini request failed: "
                + describe_error(error)
            ),
        )


# ============================================================
# 9. CONFIDENCE ROUTING
# ============================================================
#
# We combine:
#
# vector evidence
# +
# Gemini confidence
#
# We do NOT treat Gemini confidence alone as truth.
#
# ============================================================

def route_decision(
    gemini_decision: SemanticDecision,
    top_vector_score: float,
) -> Literal["AUTO_APPROVE", "REVIEW", "CREATE_NEW"]:
    """
    Convert model output into a safer operational route.

    AUTO_APPROVE:
        strong REUSE evidence

    REVIEW:
        ambiguous or moderate evidence

    CREATE_NEW:
        Gemini concludes entity is new with high confidence
    """


    # --------------------------------------------------------
    # REUSE
    # --------------------------------------------------------

    if gemini_decision.decision == "REUSE":

        if (
            gemini_decision.confidence >= 0.85
            and top_vector_score >= 0.75
        ):

            return "AUTO_APPROVE"

        return "REVIEW"


    # --------------------------------------------------------
    # NEW ENTITY
    # --------------------------------------------------------

    if gemini_decision.decision == "NEW_ENTITY":

        if gemini_decision.confidence >= 0.85:

            return "CREATE_NEW"

        return "REVIEW"


    # --------------------------------------------------------
    # UNCERTAIN
    # --------------------------------------------------------

    return "REVIEW"


# ============================================================
# 10. PROCESS EACH INCOMING ENTITY
# ============================================================

results: list[dict[str, object]] = []


incoming_ids = (
    candidate_df[
        "incoming_id"
    ]
    .unique()
)


for incoming_id in incoming_ids:

    subset: pd.DataFrame = candidate_df[
        candidate_df[
            "incoming_id"
        ]
        == incoming_id
    ].sort_values(
        "candidate_rank"
    )


    first_row: pd.Series = subset.iloc[0]


    incoming_name: str = str(
        first_row[
            "incoming_name"
        ]
    )


    entity_type: str = str(
        first_row[
            "entity_type"
        ]
    )


    top_vector_score: float = float(
        first_row[
            "similarity_score"
        ]
    )


    print("\n" + "-" * 80)

    print(
        f"Incoming: {incoming_name}"
    )

    print(
        f"Entity Type: {entity_type}"
    )

    print(
        f"Top Vector Score: "
        f"{top_vector_score}"
    )


    # ========================================================
    # CALL GEMINI
    # ========================================================

    gemini_decision = (
        get_gemini_decision(

            incoming_name,
            entity_type,
            subset,
        )
    )


    # ========================================================
    # FINAL ROUTING
    # ========================================================

    routing_decision = (
        route_decision(

            gemini_decision,
            top_vector_score,
        )
    )


    print(
        f"Gemini Decision: "
        f"{gemini_decision.decision}"
    )


    print(
        f"Gemini Confidence: "
        f"{gemini_decision.confidence}"
    )


    print(
        f"Selected Entity: "
        f"{gemini_decision.selected_canonical_name}"
    )


    print(
        f"Routing: "
        f"{routing_decision}"
    )


    print(
        f"Reasoning: "
        f"{gemini_decision.reasoning}"
    )


    results.append(
        {
            "incoming_id":
                incoming_id,

            "incoming_name":
                incoming_name,

            "entity_type":
                entity_type,

            "top_vector_score":
                top_vector_score,

            "gemini_decision":
                gemini_decision.decision,

            "selected_canonical_id":
                gemini_decision.selected_canonical_id,

            "selected_canonical_name":
                gemini_decision.selected_canonical_name,

            "gemini_confidence":
                gemini_decision.confidence,

            "routing_decision":
                routing_decision,

            "reasoning":
                gemini_decision.reasoning,
        }
    )


# ============================================================
# 11. SAVE RESULTS
# ============================================================

results_df = pd.DataFrame(
    results
)


results_df.to_csv(
    OUTPUT_FILE,
    index=False,
)


# ============================================================
# 12. SUMMARY
# ============================================================

print("\n")
print("=" * 80)
print("SEMANTIC MAPPING SUMMARY")
print("=" * 80)


print(
    "\nGemini Decisions:"
)


print(
    results_df[
        "gemini_decision"
    ]
    .value_counts()
)


print(
    "\nRouting Decisions:"
)


print(
    results_df[
        "routing_decision"
    ]
    .value_counts()
)


print(
    f"\nResults saved to:\n"
    f"{OUTPUT_FILE}"
)


print("\n")
print("=" * 80)
print("GEMINI SEMANTIC MAPPING COMPLETED")
print("=" * 80)