# ============================================================
# STAGE 12
# HUMAN REVIEW + FEEDBACK LOOP + FINAL CANONICAL MAPPING
# ============================================================
#
# PURPOSE
# -------
# This stage completes our semantic entity resolution workflow.
#
# Previous stages gave us:
#
# Incoming Entity
#      ↓
# Vector Search
#      ↓
# Gemini Semantic Decision
#      ↓
# AUTO_APPROVE / REVIEW / CREATE_NEW
#
#
# Now we add:
#
# Human Review
#      ↓
# Final Decision
#      ↓
# Canonical Mapping
#      ↓
# Feedback Dataset
#
#
# IMPORTANT
# ---------
# Reviewer decisions in this learning project are simulated.
# In production, they would come from a real analyst/reviewer.
#
# ============================================================


# pyright: reportUnknownMemberType=false
# pyright: reportUnknownArgumentType=false
# pyright: reportUnknownVariableType=false

from pathlib import Path
import pandas as pd


# ============================================================
# 1. PROJECT PATHS
# ============================================================

PROJECT_ROOT = Path(__file__).resolve().parent.parent


INPUT_FILE = (
    PROJECT_ROOT
    / "outputs"
    / "gemini_mapping"
    / "gemini_mapping_results.csv"
)


OUTPUT_DIR = (
    PROJECT_ROOT
    / "outputs"
    / "human_review"
)


OUTPUT_DIR.mkdir(
    parents=True,
    exist_ok=True,
)


REVIEW_FILE = (
    OUTPUT_DIR
    / "human_review_results.csv"
)


FINAL_MAPPING_FILE = (
    OUTPUT_DIR
    / "final_canonical_mapping.csv"
)


FEEDBACK_FILE = (
    OUTPUT_DIR
    / "semantic_mapping_feedback.csv"
)


SUMMARY_FILE = (
    OUTPUT_DIR
    / "review_summary.csv"
)


# ============================================================
# 2. LOAD GEMINI RESULTS
# ============================================================

mapping_df = pd.read_csv(
    INPUT_FILE
)


print("=" * 80)
print("HUMAN REVIEW + FEEDBACK LOOP")
print("=" * 80)


print(
    f"\nRows loaded: "
    f"{len(mapping_df)}"
)


# ============================================================
# 3. SIMULATED REVIEWER DECISIONS
# ============================================================
#
# These are learning examples only.
#
# In a real workflow:
#
# - Analyst opens REVIEW queue
# - Reviews incoming entity
# - Reviews top vector candidates
# - Reviews Gemini reasoning
# - Chooses final action
#
#
# Allowed reviewer decisions:
#
# REUSE
# NEW_ENTITY
#
# ============================================================

SIMULATED_REVIEW_DECISIONS: dict[str, dict[str, str | None]] = {

    # Threat actor aliases
    "APT29": {
        "reviewer_decision": "REUSE",
        "canonical_id": "TA001",
        "canonical_name": "APT-29",
    },

    "APT 29": {
        "reviewer_decision": "REUSE",
        "canonical_id": "TA001",
        "canonical_name": "APT-29",
    },

    "Shadow-Spider": {
        "reviewer_decision": "REUSE",
        "canonical_id": "TA002",
        "canonical_name": "Shadow Spider",
    },

    "CrimsonFox": {
        "reviewer_decision": "REUSE",
        "canonical_id": "TA003",
        "canonical_name": "Crimson Fox",
    },

    "Blue Falcon": {
        "reviewer_decision": "NEW_ENTITY",
        "canonical_id": None,
        "canonical_name": None,
    },


    # Malware aliases
    "Solar Drop": {
        "reviewer_decision": "REUSE",
        "canonical_id": "MAL001",
        "canonical_name": "SolarDrop",
    },

    "black-crypt": {
        "reviewer_decision": "REUSE",
        "canonical_id": "MAL002",
        "canonical_name": "BlackCrypt",
    },

    "Credential Fox": {
        "reviewer_decision": "REUSE",
        "canonical_id": "MAL003",
        "canonical_name": "CredentialFox",
    },

    "Silent Loader": {
        "reviewer_decision": "REUSE",
        "canonical_id": "MAL004",
        "canonical_name": "SilentLoader",
    },

    "NightCrawler": {
        "reviewer_decision": "NEW_ENTITY",
        "canonical_id": None,
        "canonical_name": None,
    },
}


# ============================================================
# 4. NEW ENTITY ID GENERATOR
# ============================================================
#
# For learning purposes:
#
# ThreatActor:
# TA9001, TA9002...
#
# Malware:
# MAL9001, MAL9002...
#
# In production, this could use:
#
# UUID
# central ID service
# ontology registry
# database sequence
#
# ============================================================

new_actor_counter = 9001
new_malware_counter = 9001


def generate_new_id(entity_type: str) -> str:
    """
    Generate a synthetic canonical ID for newly created entities.
    """

    global new_actor_counter
    global new_malware_counter


    if entity_type == "ThreatActor":

        new_id = (
            f"TA{new_actor_counter}"
        )

        new_actor_counter += 1

        return new_id


    if entity_type == "Malware":

        new_id = (
            f"MAL{new_malware_counter}"
        )

        new_malware_counter += 1

        return new_id


    return "NEW_UNKNOWN"


# ============================================================
# 5. PROCESS FINAL DECISIONS
# ============================================================

review_results: list[dict[str, object]] = []

final_mappings: list[dict[str, object]] = []

feedback_rows: list[dict[str, object]] = []


for _, row in mapping_df.iterrows():

    incoming_name = (
        row["incoming_name"]
    )

    entity_type = (
        row["entity_type"]
    )

    gemini_decision = (
        row["gemini_decision"]
    )

    routing_decision = (
        row["routing_decision"]
    )


    # ========================================================
    # CASE 1
    # AUTO_APPROVE
    # ========================================================
    #
    # Gemini + vector evidence was strong enough.
    #
    # We reuse Gemini's selected entity.
    #
    # ========================================================

    if routing_decision == "AUTO_APPROVE":

        final_decision = "REUSE"

        final_canonical_id = (
            row[
                "selected_canonical_id"
            ]
        )

        final_canonical_name = (
            row[
                "selected_canonical_name"
            ]
        )

        reviewer_decision = "NOT_REQUIRED"

        review_status = (
            "AUTO_APPROVED"
        )


    # ========================================================
    # CASE 2
    # CREATE_NEW
    # ========================================================

    elif routing_decision == "CREATE_NEW":

        final_decision = "NEW_ENTITY"

        final_canonical_id = (
            generate_new_id(
                entity_type
            )
        )

        final_canonical_name = (
            incoming_name
        )

        reviewer_decision = "NOT_REQUIRED"

        review_status = (
            "AUTO_CREATED"
        )


    # ========================================================
    # CASE 3
    # REVIEW
    # ========================================================

    else:

        reviewer_info: dict[str, str | None] | None = (
            SIMULATED_REVIEW_DECISIONS.get(
                incoming_name
            )
        )


        if reviewer_info is None:

            # Conservative fallback.
            #
            # If no reviewer result is available,
            # do not silently merge.

            reviewer_decision = (
                "UNRESOLVED"
            )

            final_decision = (
                "UNRESOLVED"
            )

            final_canonical_id = None

            final_canonical_name = None

            review_status = (
                "REVIEW_PENDING"
            )


        else:

            reviewer_decision: str = str(
                reviewer_info[
                    "reviewer_decision"
                ]
            )


            # ----------------------------------------
            # REVIEWER SAYS REUSE
            # ----------------------------------------

            if (
                reviewer_decision
                == "REUSE"
            ):

                final_decision = (
                    "REUSE"
                )

                final_canonical_id: str | None = (
                    reviewer_info[
                        "canonical_id"
                    ]
                )

                final_canonical_name: str | None = (
                    reviewer_info[
                        "canonical_name"
                    ]
                )

                review_status = (
                    "REVIEW_COMPLETED"
                )


            # ----------------------------------------
            # REVIEWER SAYS NEW ENTITY
            # ----------------------------------------

            elif (
                reviewer_decision
                == "NEW_ENTITY"
            ):

                final_decision = (
                    "NEW_ENTITY"
                )

                final_canonical_id = (
                    generate_new_id(
                        entity_type
                    )
                )

                final_canonical_name = (
                    incoming_name
                )

                review_status = (
                    "REVIEW_COMPLETED"
                )


            else:

                final_decision = (
                    "UNRESOLVED"
                )

                final_canonical_id = None

                final_canonical_name = None

                review_status = (
                    "REVIEW_PENDING"
                )


    # ========================================================
    # 6. GEMINI vs FINAL AGREEMENT
    # ========================================================
    #
    # We compare the semantic category:
    #
    # Gemini:
    # REUSE / NEW_ENTITY / UNCERTAIN
    #
    # Final:
    # REUSE / NEW_ENTITY / UNRESOLVED
    #
    # ========================================================

    agreement = (
        gemini_decision
        == final_decision
    )


    # ========================================================
    # 7. STORE REVIEW RESULT
    # ========================================================

    review_results.append(
        {
            "incoming_name":
                incoming_name,

            "entity_type":
                entity_type,

            "gemini_decision":
                gemini_decision,

            "routing_decision":
                routing_decision,

            "reviewer_decision":
                reviewer_decision,

            "final_decision":
                final_decision,

            "final_canonical_id":
                final_canonical_id,

            "final_canonical_name":
                final_canonical_name,

            "review_status":
                review_status,

            "gemini_final_agreement":
                agreement,
        }
    )


    # ========================================================
    # 8. FINAL CANONICAL MAPPING
    # ========================================================

    final_mappings.append(
        {
            "incoming_id":
                row["incoming_id"],

            "incoming_name":
                incoming_name,

            "entity_type":
                entity_type,

            "final_decision":
                final_decision,

            "canonical_id":
                final_canonical_id,

            "canonical_name":
                final_canonical_name,
        }
    )


    # ========================================================
    # 9. FEEDBACK DATASET
    # ========================================================
    #
    # This captures:
    #
    # incoming
    # vector score
    # Gemini prediction
    # Gemini confidence
    # Gemini reasoning
    # reviewer/final outcome
    #
    # Later this can support:
    #
    # - threshold tuning
    # - evaluation
    # - prompt improvement
    # - supervised training examples
    #
    # ========================================================

    feedback_rows.append(
        {
            "incoming_id":
                row["incoming_id"],

            "incoming_name":
                incoming_name,

            "entity_type":
                entity_type,

            "top_vector_score":
                row["top_vector_score"],

            "gemini_decision":
                gemini_decision,

            "gemini_confidence":
                row["gemini_confidence"],

            "gemini_selected_id":
                row[
                    "selected_canonical_id"
                ],

            "gemini_selected_name":
                row[
                    "selected_canonical_name"
                ],

            "gemini_reasoning":
                row["reasoning"],

            "routing_decision":
                routing_decision,

            "reviewer_decision":
                reviewer_decision,

            "final_decision":
                final_decision,

            "final_canonical_id":
                final_canonical_id,

            "final_canonical_name":
                final_canonical_name,

            "agreement":
                agreement,
        }
    )


# ============================================================
# 10. CREATE DATAFRAMES
# ============================================================

review_df = pd.DataFrame(
    review_results
)


final_mapping_df = pd.DataFrame(
    final_mappings
)


feedback_df = pd.DataFrame(
    feedback_rows
)


# ============================================================
# 11. AGREEMENT METRICS
# ============================================================

resolved_feedback = feedback_df[
    feedback_df[
        "final_decision"
    ]
    != "UNRESOLVED"
]


total_resolved = len(
    resolved_feedback
)


agreements = (
    resolved_feedback[
        "agreement"
    ]
    .sum()
)


agreement_rate = (
    agreements
    / total_resolved
    * 100
    if total_resolved > 0
    else 0
)


# ============================================================
# 12. REVIEW QUEUE METRICS
# ============================================================

total_rows = len(
    mapping_df
)


review_cases = len(
    mapping_df[
        mapping_df[
            "routing_decision"
        ]
        == "REVIEW"
    ]
)


auto_approved = len(
    mapping_df[
        mapping_df[
            "routing_decision"
        ]
        == "AUTO_APPROVE"
    ]
)


auto_created = len(
    mapping_df[
        mapping_df[
            "routing_decision"
        ]
        == "CREATE_NEW"
    ]
)


# ============================================================
# 13. CREATE SUMMARY
# ============================================================

summary_df = pd.DataFrame(
    [
        {
            "total_entities":
                total_rows,

            "auto_approved":
                auto_approved,

            "review_cases":
                review_cases,

            "auto_created":
                auto_created,

            "gemini_final_agreement_percent":
                round(
                    agreement_rate,
                    2,
                ),
        }
    ]
)


# ============================================================
# 14. SAVE OUTPUT FILES
# ============================================================

review_df.to_csv(
    REVIEW_FILE,
    index=False,
)


final_mapping_df.to_csv(
    FINAL_MAPPING_FILE,
    index=False,
)


feedback_df.to_csv(
    FEEDBACK_FILE,
    index=False,
)


summary_df.to_csv(
    SUMMARY_FILE,
    index=False,
)


# ============================================================
# 15. DISPLAY RESULTS
# ============================================================

print("\n")
print("=" * 80)
print("FINAL CANONICAL MAPPINGS")
print("=" * 80)


for _, row in (
    final_mapping_df.iterrows()
):

    print("\n" + "-" * 80)

    print(
        f"Incoming: "
        f"{row['incoming_name']}"
    )

    print(
        f"Final Decision: "
        f"{row['final_decision']}"
    )

    print(
        f"Canonical ID: "
        f"{row['canonical_id']}"
    )

    print(
        f"Canonical Name: "
        f"{row['canonical_name']}"
    )


# ============================================================
# 16. FINAL SUMMARY
# ============================================================

print("\n")
print("=" * 80)
print("HUMAN REVIEW SUMMARY")
print("=" * 80)


print(
    f"\nTotal entities: "
    f"{total_rows}"
)


print(
    f"Auto-approved: "
    f"{auto_approved}"
)


print(
    f"Review cases: "
    f"{review_cases}"
)


print(
    f"Auto-created: "
    f"{auto_created}"
)


print(
    f"Gemini vs Final Agreement: "
    f"{agreement_rate:.2f}%"
)


print(
    f"\nReview results:\n"
    f"{REVIEW_FILE}"
)


print(
    f"\nFinal canonical mappings:\n"
    f"{FINAL_MAPPING_FILE}"
)


print(
    f"\nFeedback dataset:\n"
    f"{FEEDBACK_FILE}"
)


print(
    f"\nSummary:\n"
    f"{SUMMARY_FILE}"
)


print("\n")
print("=" * 80)
print("HUMAN REVIEW + FEEDBACK LOOP COMPLETED")
print("=" * 80)