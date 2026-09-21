# ============================================================
# STAGE 9
# ENTITY RESOLUTION + SEMANTIC DEDUPLICATION
# ============================================================
#
# PURPOSE
# -------
# Knowledge Graph data may contain different textual forms
# referring to the same logical entity.
#
# Examples:
#
#   APT-29
#   APT29
#   APT 29
#
# Or:
#
#   SolarDrop
#   Solar Drop
#   solar-drop
#
# In this stage we will:
#
# 1. Load canonical Knowledge Graph entities
# 2. Create synthetic incoming records
# 3. Normalize names
# 4. Generate TF-IDF text vectors
# 5. Calculate cosine similarity
# 6. Find the best canonical candidate
# 7. Apply confidence-based routing
# 8. Save an entity-resolution report
#
# ============================================================


from pathlib import Path
import re
from typing import Any

import pandas as pd

from sklearn.feature_extraction.text import (
    TfidfVectorizer,
)

from sklearn.metrics.pairwise import (
    cosine_similarity,
)


# ============================================================
# 1. PROJECT PATHS
# ============================================================

PROJECT_ROOT = Path(__file__).resolve().parent.parent

RAW_DATA_DIR = (
    PROJECT_ROOT
    / "data"
    / "raw"
)

PROCESSED_DATA_DIR = (
    PROJECT_ROOT
    / "data"
    / "processed"
)

OUTPUT_DIR = (
    PROJECT_ROOT
    / "outputs"
    / "entity_resolution"
)


PROCESSED_DATA_DIR.mkdir(
    parents=True,
    exist_ok=True,
)

OUTPUT_DIR.mkdir(
    parents=True,
    exist_ok=True,
)


INCOMING_FILE = (
    PROCESSED_DATA_DIR
    / "incoming_entity_candidates.csv"
)


RESULT_FILE = (
    OUTPUT_DIR
    / "entity_resolution_results.csv"
)


# ============================================================
# 2. CONFIDENCE THRESHOLDS
# ============================================================
#
# These thresholds are project-specific.
#
# AUTO_MATCH
# ----------
# High-confidence candidate.
#
# REVIEW
# ------
# Possible match, but human review is preferred.
#
# NEW_ENTITY
# ----------
# Similarity is too low, so we do not automatically merge.
#
# ============================================================

AUTO_MATCH_THRESHOLD = 0.82

REVIEW_THRESHOLD = 0.60


# ============================================================
# 3. NORMALIZATION FUNCTION
# ============================================================

def normalize_name(text: Any) -> str:
    """
    Normalize an entity name before comparison.

    Example:

        "APT-29"
        "APT 29"
        "APT29"

    all become approximately:

        "apt29"

    We:
    - lowercase
    - remove spaces
    - remove punctuation
    - keep only letters and numbers
    """

    if pd.isna(text):
        return ""

    text = str(text).lower()

    text = re.sub(
        r"[^a-z0-9]",
        "",
        text,
    )

    return text


# ============================================================
# 4. LOAD CANONICAL THREAT ACTORS
# ============================================================

threat_actors = pd.read_csv(
    RAW_DATA_DIR
    / "threat_actors.csv"
)


canonical_actors = threat_actors[
    [
        "actor_id",
        "actor_name",
    ]
].copy()


canonical_actors.columns = [
    "canonical_id",
    "canonical_name",
]


canonical_actors[
    "entity_type"
] = "ThreatActor"


# ============================================================
# 5. LOAD CANONICAL MALWARE
# ============================================================

malware = pd.read_csv(
    RAW_DATA_DIR
    / "malware.csv"
)


canonical_malware = malware[
    [
        "malware_id",
        "malware_name",
    ]
].copy()


canonical_malware.columns = [
    "canonical_id",
    "canonical_name",
]


canonical_malware[
    "entity_type"
] = "Malware"


# ============================================================
# 6. COMBINE CANONICAL ENTITIES
# ============================================================

canonical_entities = pd.concat(
    [
        canonical_actors,
        canonical_malware,
    ],
    ignore_index=True,
)


canonical_entities[
    "normalized_name"
] = canonical_entities[
    "canonical_name"
].apply(
    normalize_name
)


# ============================================================
# 7. CREATE SYNTHETIC INCOMING RECORDS
# ============================================================
#
# Imagine these records arrived from:
#
# - external threat feeds
# - CSV ingestion
# - security reports
# - analyst submissions
#
# Some are duplicates.
# Some are variations.
# Some are genuinely new.
#
# ============================================================

incoming_entities = pd.DataFrame(
    [
        # --------------------------------------------
        # Threat Actor variations
        # --------------------------------------------

        [
            "INC001",
            "APT29",
            "ThreatActor",
        ],

        [
            "INC002",
            "APT 29",
            "ThreatActor",
        ],

        [
            "INC003",
            "Shadow-Spider",
            "ThreatActor",
        ],

        [
            "INC004",
            "CrimsonFox",
            "ThreatActor",
        ],

        # New threat actor.
        [
            "INC005",
            "Blue Falcon",
            "ThreatActor",
        ],


        # --------------------------------------------
        # Malware variations
        # --------------------------------------------

        [
            "INC006",
            "Solar Drop",
            "Malware",
        ],

        [
            "INC007",
            "black-crypt",
            "Malware",
        ],

        [
            "INC008",
            "Credential Fox",
            "Malware",
        ],

        [
            "INC009",
            "Silent Loader",
            "Malware",
        ],

        # New malware.
        [
            "INC010",
            "NightCrawler",
            "Malware",
        ],
    ],
    columns=[
        "incoming_id",
        "incoming_name",
        "entity_type",
    ],
)


incoming_entities.to_csv(
    INCOMING_FILE,
    index=False,
)


incoming_entities[
    "normalized_name"
] = incoming_entities[
    "incoming_name"
].apply(
    normalize_name
)


# ============================================================
# 8. ENTITY RESOLUTION FUNCTION
# ============================================================

def resolve_entity(
    incoming_row: pd.Series,
    canonical_df: pd.DataFrame,
) -> dict[str, Any]:
    """
    Resolve one incoming entity against canonical entities
    of the same entity type.

    Resolution steps:

    1. Filter by entity type.
    2. Check exact normalized match.
    3. If no exact match, calculate TF-IDF similarity.
    4. Select best candidate.
    5. Apply confidence-routing decision.
    """

    incoming_name = (
        incoming_row[
            "incoming_name"
        ]
    )

    normalized_incoming = (
        incoming_row[
            "normalized_name"
        ]
    )

    entity_type = (
        incoming_row[
            "entity_type"
        ]
    )


    # ========================================================
    # FILTER CANDIDATES BY ENTITY TYPE
    # ========================================================

    candidates = canonical_df.loc[
        canonical_df["entity_type"].eq(entity_type)
    ].copy()


    # ========================================================
    # EXACT NORMALIZED MATCH
    # ========================================================
    #
    # Example:
    #
    # canonical:
    # APT-29 -> apt29
    #
    # incoming:
    # APT 29 -> apt29
    #
    # This can safely be considered an exact normalized match.
    #
    # ========================================================

    exact_matches = candidates[
        candidates[
            "normalized_name"
        ]
        == normalized_incoming
    ]


    if not exact_matches.empty: # type: ignore

        best_match = exact_matches.head(1).squeeze("index") # type: ignore

        return {
            "incoming_id":
                incoming_row[
                    "incoming_id"
                ],

            "incoming_name":
                incoming_name,

            "entity_type":
                entity_type,

            "canonical_id":
                best_match[
                    "canonical_id"
                ],

            "canonical_name":
                best_match[
                    "canonical_name"
                ],

            "similarity_score":
                1.0,

            "match_method":
                "NORMALIZED_EXACT_MATCH",

            "decision":
                "AUTO_MATCH",
        }


    # ========================================================
    # TF-IDF CANDIDATE SIMILARITY
    # ========================================================
    #
    # Character n-grams work well for small spelling and
    # formatting differences.
    #
    # Example:
    #
    # SolarDrop
    # Solar Drop
    #
    # Their character patterns are highly similar.
    #
    # ========================================================

    comparison_names = (
        candidates[
            "canonical_name"
        ].tolist()
        + [
            incoming_name
        ]
    )


    vectorizer = TfidfVectorizer(

        # Character-level representation.
        analyzer="char_wb",

        # Use sequences of 2 to 4 characters.
        ngram_range=(
            2,
            4,
        ),

        lowercase=True,
    )


    vectors = vectorizer.fit_transform(
        comparison_names
    )


    # Last vector belongs to incoming entity.
    incoming_vector = vectors[-1]


    # Other vectors belong to canonical candidates.
    candidate_vectors = vectors[:-1]


    similarities = cosine_similarity(
        incoming_vector,
        candidate_vectors,
    )[0]


    # Find highest similarity.
    best_position = (
        similarities.argmax()
    )


    best_score = float(
        similarities[
            best_position
        ]
    )


    best_match = candidates.iloc[
        best_position
    ]


    # ========================================================
    # CONFIDENCE-BASED ROUTING
    # ========================================================

    if best_score >= AUTO_MATCH_THRESHOLD:

        decision = "AUTO_MATCH"

    elif best_score >= REVIEW_THRESHOLD:

        decision = "REVIEW"

    else:

        decision = "NEW_ENTITY"


    return {
        "incoming_id":
            incoming_row[
                "incoming_id"
            ],

        "incoming_name":
            incoming_name,

        "entity_type":
            entity_type,

        "canonical_id":
            best_match[
                "canonical_id"
            ],

        "canonical_name":
            best_match[
                "canonical_name"
            ],

        "similarity_score":
            round(
                best_score,
                4,
            ),

        "match_method":
            "TFIDF_CHAR_SIMILARITY",

        "decision":
            decision,
    }


# ============================================================
# 9. RUN ENTITY RESOLUTION
# ============================================================

resolution_results: list[dict[str, Any]] = []


for _, incoming_row in (
    incoming_entities.iterrows()
):

    result = resolve_entity(
        incoming_row,
        canonical_entities,
    )

    resolution_results.append(
        result
    )


results_df = pd.DataFrame(
    resolution_results
)


# ============================================================
# 10. SAVE RESULTS
# ============================================================

results_df.to_csv(
    RESULT_FILE,
    index=False,
)


# ============================================================
# 11. DISPLAY RESULTS
# ============================================================

print("=" * 80)
print("CYBERSECURITY ENTITY RESOLUTION")
print("=" * 80)


for _, row in results_df.iterrows():

    print("\n" + "-" * 80)

    print(
        f"Incoming: "
        f"{row['incoming_name']}"
    )

    print(
        f"Entity Type: "
        f"{row['entity_type']}"
    )

    print(
        f"Best Candidate: "
        f"{row['canonical_name']}"
    )

    print(
        f"Canonical ID: "
        f"{row['canonical_id']}"
    )

    print(
        f"Similarity: "
        f"{row['similarity_score']}"
    )

    print(
        f"Method: "
        f"{row['match_method']}"
    )

    print(
        f"Decision: "
        f"{row['decision']}"
    )


# ============================================================
# 12. DECISION SUMMARY
# ============================================================

decision_summary = (
    results_df[
        "decision"
    ]
    .value_counts()
)


print("\n")
print("=" * 80)
print("ENTITY RESOLUTION SUMMARY")
print("=" * 80)


for decision, count in (
    decision_summary.items()
):

    print(
        f"{decision:<15}: "
        f"{count}"
    )


print(
    f"\nResults saved to:\n"
    f"{RESULT_FILE}"
)


print("\n")
print("=" * 80)
print("ENTITY RESOLUTION COMPLETED")
print("=" * 80)