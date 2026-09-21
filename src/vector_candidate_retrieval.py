# ============================================================
# STAGE 10
# EMBEDDINGS + VECTOR CANDIDATE RETRIEVAL
# ============================================================
#
# PURPOSE
# -------
# This stage upgrades our entity-resolution workflow.
#
# Instead of relying only on string similarity, we represent
# entities as numerical embedding vectors.
#
# Workflow:
#
# Canonical Entity
#       ↓
# Build Entity Description
#       ↓
# Embedding Model
#       ↓
# Vector
#
#
# Incoming Entity
#       ↓
# Build Description
#       ↓
# Embedding
#       ↓
# Cosine Similarity
#       ↓
# Top-K Existing Candidates
#
#
# Later Gemini will inspect these candidates and decide:
#
# REUSE
# NEW_ENTITY
# UNCERTAIN
#
# ============================================================


from pathlib import Path
from typing import Any

import pandas as pd
import numpy as np

from sentence_transformers import (
    SentenceTransformer,
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
    / "vector_search"
)


OUTPUT_DIR.mkdir(
    parents=True,
    exist_ok=True,
)


INCOMING_FILE = (
    PROCESSED_DATA_DIR
    / "incoming_entity_candidates.csv"
)


OUTPUT_FILE = (
    OUTPUT_DIR
    / "vector_candidate_results.csv"
)


# ============================================================
# 2. CONFIGURATION
# ============================================================

# Small general-purpose embedding model.
#
# Good for learning and local experimentation.
#
MODEL_NAME = (
    "sentence-transformers/"
    "all-MiniLM-L6-v2"
)


# Number of candidates retrieved for every incoming entity.
TOP_K = 3


# ============================================================
# 3. LOAD CANONICAL DATA
# ============================================================

threat_actors = pd.read_csv(
    RAW_DATA_DIR
    / "threat_actors.csv"
)


malware = pd.read_csv(
    RAW_DATA_DIR
    / "malware.csv"
)


incoming_entities = pd.read_csv(
    INCOMING_FILE
)


# ============================================================
# 4. CREATE RICH THREAT ACTOR DESCRIPTIONS
# ============================================================
#
# Embeddings work better when we provide more semantic
# information than only the entity name.
#
# Instead of:
#
# APT-29
#
# we generate:
#
# Threat Actor: APT-29.
# Type: State-Sponsored.
# Primary motivation: Credential Theft.
#
# ============================================================

actor_records: list[dict[str, Any]] = []


for _, row in threat_actors.iterrows():

    description = (
        f"Threat Actor: {row['actor_name']}. "
        f"Type: {row['actor_type']}. "
        f"Primary motivation: "
        f"{row['primary_motivation']}."
    )


    actor_records.append(
        {
            "canonical_id":
                row["actor_id"],

            "canonical_name":
                row["actor_name"],

            "entity_type":
                "ThreatActor",

            "description":
                description,
        }
    )


# ============================================================
# 5. CREATE RICH MALWARE DESCRIPTIONS
# ============================================================

malware_records: list[dict[str, Any]] = []


for _, row in malware.iterrows():

    description = (
        f"Malware: {row['malware_name']}. "
        f"Malware type: {row['malware_type']}."
    )


    malware_records.append(
        {
            "canonical_id":
                row["malware_id"],

            "canonical_name":
                row["malware_name"],

            "entity_type":
                "Malware",

            "description":
                description,
        }
    )


# ============================================================
# 6. COMBINE CANONICAL ENTITY CATALOG
# ============================================================

canonical_entities = pd.DataFrame(
    actor_records
    + malware_records
)


print("=" * 80)
print("VECTOR CANDIDATE RETRIEVAL")
print("=" * 80)


print(
    f"\nCanonical entities loaded: "
    f"{len(canonical_entities)}"
)


print(
    f"Incoming entities loaded: "
    f"{len(incoming_entities)}"
)


# ============================================================
# 7. LOAD EMBEDDING MODEL
# ============================================================

print(
    "\nLoading embedding model..."
)


model = SentenceTransformer(
    MODEL_NAME
)


print(
    f"Model loaded: {MODEL_NAME}"
)


# ============================================================
# 8. GENERATE CANONICAL ENTITY EMBEDDINGS
# ============================================================
#
# normalize_embeddings=True creates unit-length vectors.
#
# This allows us to use a simple dot product as cosine
# similarity.
#
# ============================================================

canonical_embeddings = model.encode(

    canonical_entities[
        "description"
    ].tolist(),

    normalize_embeddings=True,

    show_progress_bar=False,
)


print(
    "\nCanonical embeddings created."
)


print(
    f"Embedding matrix shape: "
    f"{canonical_embeddings.shape}"
)


# ============================================================
# 9. BUILD INCOMING ENTITY DESCRIPTION
# ============================================================

def build_incoming_description(
    row: pd.Series,
) -> str:
    """
    Build a text representation for an incoming entity.

    At this stage our incoming dataset only contains
    name and entity type.

    Later we can enrich this with:
    - aliases
    - malware behavior
    - attack techniques
    - infrastructure
    - source metadata
    - campaign context
    """

    entity_type = str(row[
        "entity_type"
    ])

    incoming_name = str(row[
        "incoming_name"
    ])


    if entity_type == "ThreatActor":

        return (
            f"Threat Actor: "
            f"{incoming_name}."
        )


    if entity_type == "Malware":

        return (
            f"Malware: "
            f"{incoming_name}."
        )


    return (
        f"{entity_type}: "
        f"{incoming_name}."
    )


# ============================================================
# 10. COSINE SIMILARITY
# ============================================================
#
# Because our embeddings are normalized:
#
# cosine similarity =
#
# vector_a dot vector_b
#
# ============================================================

def cosine_scores(
    query_embedding: Any,
    candidate_embeddings: Any,
) -> Any:

    return np.dot(
        candidate_embeddings,
        query_embedding,
    )


# ============================================================
# 11. RETRIEVE TOP-K CANDIDATES
# ============================================================

def retrieve_candidates(
    incoming_row: pd.Series,
) -> list[dict[str, Any]]:
    """
    Retrieve the most semantically similar canonical
    entities for one incoming record.

    IMPORTANT:
    We only compare entities belonging to the same class.

    ThreatActor -> ThreatActor candidates

    Malware -> Malware candidates
    """

    entity_type = str(
        incoming_row[
            "entity_type"
        ]
    )


    incoming_description = (
        build_incoming_description(
            incoming_row
        )
    )


    # ========================================================
    # GENERATE QUERY EMBEDDING
    # ========================================================

    incoming_embedding = model.encode(

        incoming_description,

        normalize_embeddings=True,

        show_progress_bar=False,
    )


    # ========================================================
    # FILTER CANONICAL ENTITIES BY TYPE
    # ========================================================

    type_mask = (
        canonical_entities[
            "entity_type"
        ]
        == entity_type
    ).to_numpy()


    candidate_indices = np.where(
        type_mask
    )[0]


    candidate_df = (
        canonical_entities[
            type_mask
        ]
        .reset_index(
            drop=True
        )
    )

    if candidate_df.empty:
        return []


    candidate_embeddings = (
        canonical_embeddings[
            candidate_indices
        ]
    )


    # ========================================================
    # CALCULATE SIMILARITY
    # ========================================================

    scores = cosine_scores(
        incoming_embedding,
        candidate_embeddings,
    )


    # ========================================================
    # SORT CANDIDATES
    # ========================================================

    ranked_positions = np.argsort(
        scores
    )[::-1]


    ranked_positions = (
        ranked_positions[
            :TOP_K
        ]
    )


    results: list[dict[str, Any]] = []


    # ========================================================
    # RETURN TOP-K
    # ========================================================

    for rank, position in enumerate(
        ranked_positions,
        start=1,
    ):

        position = int(position)

        candidate = (
            candidate_df.iloc[
                position
            ]
        )


        score = float(
            scores[
                position
            ]
        )


        results.append(
            {
                "incoming_id":
                    incoming_row[
                        "incoming_id"
                    ],

                "incoming_name":
                    incoming_row[
                        "incoming_name"
                    ],

                "entity_type":
                    entity_type,

                "candidate_rank":
                    rank,

                "canonical_id":
                    candidate[
                        "canonical_id"
                    ],

                "canonical_name":
                    candidate[
                        "canonical_name"
                    ],

                "similarity_score":
                    round(
                        score,
                        4,
                    ),

                "canonical_description":
                    candidate[
                        "description"
                    ],
            }
        )


    return results


# ============================================================
# 12. RUN VECTOR RETRIEVAL
# ============================================================

all_results: list[dict[str, Any]] = []


for _, incoming_row in (
    incoming_entities.iterrows()
):

    candidate_results = (
        retrieve_candidates(
            incoming_row
        )
    )


    all_results.extend(
        candidate_results
    )


results_df = pd.DataFrame(
    all_results
)


# ============================================================
# 13. SAVE RESULTS
# ============================================================

results_df.to_csv(
    OUTPUT_FILE,
    index=False,
)


# ============================================================
# 14. DISPLAY CANDIDATES
# ============================================================

for incoming_id in (
    results_df[
        "incoming_id"
    ].unique()
):

    subset = results_df[
        results_df[
            "incoming_id"
        ]
        == incoming_id
    ]


    first_row = subset.head(1).squeeze("index")


    print("\n")
    print("-" * 80)

    print(
        f"Incoming Entity: "
        f"{first_row['incoming_name']}"
    )


    print(
        f"Entity Type: "
        f"{first_row['entity_type']}"
    )


    print(
        "\nTop Candidates:"
    )


    for _, candidate in (
        subset.iterrows()
    ):

        print(
            f"  Rank "
            f"{candidate['candidate_rank']}: "
            f"{candidate['canonical_name']} "
            f"({candidate['canonical_id']}) "
            f"Score="
            f"{candidate['similarity_score']}"
        )


# ============================================================
# 15. DISPLAY BEST CANDIDATE SUMMARY
# ============================================================

best_candidates = (
    results_df[
        results_df[
            "candidate_rank"
        ]
        == 1
    ]
)


print("\n")
print("=" * 80)
print("BEST CANDIDATE SUMMARY")
print("=" * 80)


for _, row in (
    best_candidates.iterrows()
):

    print(
        f"\n"
        f"{row['incoming_name']:<20}"
        f" -> "
        f"{row['canonical_name']:<20}"
        f" Score: "
        f"{row['similarity_score']}"
    )


# ============================================================
# 16. FINAL OUTPUT
# ============================================================

print("\n")
print("=" * 80)
print("VECTOR RETRIEVAL COMPLETED")
print("=" * 80)


print(
    f"\nResults saved to:\n"
    f"{OUTPUT_FILE}"
)