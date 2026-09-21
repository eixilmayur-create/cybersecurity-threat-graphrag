# ============================================================
# STAGE 13
# GRAPH-RAG RETRIEVAL PIPELINE
# ============================================================
#
# PURPOSE
# -------
# Convert a natural-language cybersecurity question into
# structured Knowledge Graph context.
#
# Workflow:
#
# User Question
#      ↓
# Detect Known Entity Name
#      ↓
# Resolve to Canonical Graph Entity
#      ↓
# Run SPARQL Multi-Hop Query
#      ↓
# Build Structured Context
#
# This context will be sent to Gemini in Stage 14.
#
# ============================================================


# pyright: reportUnknownMemberType=false
# pyright: reportUnknownArgumentType=false
# pyright: reportUnknownVariableType=false

from pathlib import Path
import re
import argparse
import json
from typing import Any, cast

import pandas as pd

from rdflib import Graph


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


GRAPH_FILE = (
    PROJECT_ROOT
    / "data"
    / "rdf"
    / "cybersecurity_knowledge_graph.ttl"
)


RAW_DATA_DIR = (
    PROJECT_ROOT
    / "data"
    / "raw"
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


OUTPUT_FILE = (
    OUTPUT_DIR
    / "retrieved_graph_context.json"
)


# ============================================================
# 2. LOAD RDF GRAPH
# ============================================================

graph = Graph()


print("=" * 80)
print("GRAPH-RAG RETRIEVAL PIPELINE")
print("=" * 80)


graph.parse(
    GRAPH_FILE,
    format="turtle",
)


print(
    f"\nKnowledge Graph triples loaded: "
    f"{len(graph)}"
)


# ============================================================
# 3. LOAD ENTITY CATALOG
# ============================================================
#
# We create a small searchable dictionary from our canonical
# source data.
#
# In later stages this can be replaced with:
#
# - embeddings
# - vector search
# - alias resolution
# - Gemini query understanding
#
# ============================================================

threat_actors = pd.read_csv(
    RAW_DATA_DIR
    / "threat_actors.csv"
)


malware = pd.read_csv(
    RAW_DATA_DIR
    / "malware.csv"
)


campaigns = pd.read_csv(
    RAW_DATA_DIR
    / "campaigns.csv"
)


organizations = pd.read_csv(
    RAW_DATA_DIR
    / "organizations.csv"
)


domains = pd.read_csv(
    RAW_DATA_DIR
    / "domains.csv"
)


vulnerabilities = pd.read_csv(
    RAW_DATA_DIR
    / "vulnerabilities.csv"
)


# ============================================================
# 4. BUILD ENTITY SEARCH CATALOG
# ============================================================

entity_catalog: list[dict[str, str | object]] = []


# Threat Actors

for _, row in threat_actors.iterrows():

    entity_catalog.append(
        {
            "entity_id":
                row["actor_id"],

            "entity_name":
                row["actor_name"],

            "entity_type":
                "ThreatActor",
        }
    )


# Malware

for _, row in malware.iterrows():

    entity_catalog.append(
        {
            "entity_id":
                row["malware_id"],

            "entity_name":
                row["malware_name"],

            "entity_type":
                "Malware",
        }
    )


# Campaigns

for _, row in campaigns.iterrows():

    entity_catalog.append(
        {
            "entity_id":
                row["campaign_id"],

            "entity_name":
                row["campaign_name"],

            "entity_type":
                "Campaign",
        }
    )


# Organizations

for _, row in organizations.iterrows():

    entity_catalog.append(
        {
            "entity_id":
                row["organization_id"],

            "entity_name":
                row["organization_name"],

            "entity_type":
                "Organization",
        }
    )


# Domains

for _, row in domains.iterrows():

    entity_catalog.append(
        {
            "entity_id":
                row["domain_id"],

            "entity_name":
                row["domain_name"],

            "entity_type":
                "Domain",
        }
    )


# Vulnerabilities

for _, row in vulnerabilities.iterrows():

    entity_catalog.append(
        {
            "entity_id":
                row["cve_id"],

            "entity_name":
                row["cve_id"],

            "entity_type":
                "Vulnerability",
        }
    )


entity_catalog_df = pd.DataFrame(
    entity_catalog
)


# ============================================================
# 5. NORMALIZATION
# ============================================================

def normalize_text(text: str | object) -> str:
    """
    Normalize text to improve simple entity matching.

    Example:

    APT-29
    APT 29
    APT29

    all become similar forms.
    """

    text_value = str(text).lower()

    return re.sub(
        r"[^a-z0-9]",
        "",
        text_value,
    )


# ============================================================
# 6. ENTITY DETECTION FROM QUESTION
# ============================================================

def detect_entity(
    question: str,
) -> dict[str, object] | None:
    """
    Find a known graph entity mentioned in the user's question.

    For this learning version, we use deterministic
    normalized name matching.

    Stage 10 already demonstrated embedding/vector retrieval,
    so later we can replace this with semantic lookup.
    """

    normalized_question = (
        normalize_text(
            question
        )
    )


    candidates: list[dict[str, object]] = []


    for _, row in (
        entity_catalog_df.iterrows()
    ):

        normalized_name = (
            normalize_text(
                row["entity_name"]
            )
        )


        if (
            normalized_name
            and normalized_name
            in normalized_question
        ):

            candidates.append(
                {
                    "entity_id":
                        row["entity_id"],

                    "entity_name":
                        row["entity_name"],

                    "entity_type":
                        row["entity_type"],

                    "name_length":
                        len(
                            normalized_name
                        ),
                }
            )


    if not candidates:

        return None


    # Prefer longest matching entity name.
    #
    # This reduces cases where a shorter name accidentally
    # matches inside a longer entity.

    candidates = sorted(
        candidates,
        key=lambda x: int(cast(int, x["name_length"])),
        reverse=True,
    )


    return candidates[0]


# ============================================================
# 7. SPARQL PREFIX
# ============================================================

PREFIXES = """
PREFIX ex: <http://example.org/cybersecurity/>
PREFIX rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#>
"""


# ============================================================
# 8. THREAT ACTOR RETRIEVAL
# ============================================================

def retrieve_threat_actor_context(
    entity_id: str,
) -> list[dict[str, object]]:
    """
    Retrieve full context around a Threat Actor.

    Paths:

    Actor -> Malware -> Vulnerability

    Actor -> Malware -> Domain -> IP

    Actor -> Campaign -> Organization
    """

    query = f"""
    SELECT
        ?actorName
        ?actorType
        ?motivation
        ?malwareName
        ?malwareType
        ?cve
        ?severity
        ?cvss
        ?domainName
        ?ipAddress
        ?campaignName
        ?attackVector
        ?organizationName
        ?industry

    WHERE {{

        ex:{entity_id}
            ex:actorName
            ?actorName .

        OPTIONAL {{
            ex:{entity_id}
                ex:actorType
                ?actorType .
        }}

        OPTIONAL {{
            ex:{entity_id}
                ex:primaryMotivation
                ?motivation .
        }}


        # ================================================
        # ACTOR -> MALWARE
        # ================================================

        OPTIONAL {{

            ex:{entity_id}
                ex:usesMalware
                ?malware .

            ?malware
                ex:malwareName
                ?malwareName .

            OPTIONAL {{
                ?malware
                    ex:malwareType
                    ?malwareType .
            }}


            # ============================================
            # MALWARE -> VULNERABILITY
            # ============================================

            OPTIONAL {{

                ?malware
                    ex:exploits
                    ?vulnerability .

                ?vulnerability
                    ex:cveId
                    ?cve .

                OPTIONAL {{
                    ?vulnerability
                        ex:severity
                        ?severity .
                }}

                OPTIONAL {{
                    ?vulnerability
                        ex:cvssScore
                        ?cvss .
                }}
            }}


            # ============================================
            # MALWARE -> DOMAIN -> IP
            # ============================================

            OPTIONAL {{

                ?malware
                    ex:communicatesWith
                    ?domain .

                ?domain
                    ex:domainName
                    ?domainName .

                OPTIONAL {{

                    ?domain
                        ex:resolvesTo
                        ?ip .

                    ?ip
                        ex:ipAddress
                        ?ipAddress .
                }}
            }}
        }}


        # ================================================
        # ACTOR -> CAMPAIGN -> ORGANIZATION
        # ================================================

        OPTIONAL {{

            ex:{entity_id}
                ex:attributedToCampaign
                ?campaign .

            ?campaign
                ex:campaignName
                ?campaignName .

            OPTIONAL {{
                ?campaign
                    ex:attackVector
                    ?attackVector .
            }}

            OPTIONAL {{

                ?campaign
                    ex:targets
                    ?organization .

                ?organization
                    ex:organizationName
                    ?organizationName .

                OPTIONAL {{
                    ?organization
                        ex:industry
                        ?industry .
                }}
            }}
        }}
    }}
    """


    results = graph.query(
        PREFIXES + query
    )


    rows: list[dict[str, Any]] = []


    for row in results:

        row_obj: Any = cast(Any, row)

        rows.append(
            {
                "actor_name":
                    str(row_obj.actorName)
                    if getattr(row_obj, "actorName", None) is not None
                    else None,

                "actor_type":
                    str(row_obj.actorType)
                    if getattr(row_obj, "actorType", None) is not None
                    else None,

                "primary_motivation":
                    str(row_obj.motivation)
                    if getattr(row_obj, "motivation", None) is not None
                    else None,

                "malware_name":
                    str(row_obj.malwareName)
                    if getattr(row_obj, "malwareName", None) is not None
                    else None,

                "malware_type":
                    str(row_obj.malwareType)
                    if getattr(row_obj, "malwareType", None) is not None
                    else None,

                "cve":
                    str(row_obj.cve)
                    if getattr(row_obj, "cve", None) is not None
                    else None,

                "severity":
                    str(row_obj.severity)
                    if getattr(row_obj, "severity", None) is not None
                    else None,

                "cvss":
                    float(row_obj.cvss)
                    if getattr(row_obj, "cvss", None) is not None
                    else None,

                "domain_name":
                    str(row_obj.domainName)
                    if getattr(row_obj, "domainName", None) is not None
                    else None,

                "ip_address":
                    str(row_obj.ipAddress)
                    if getattr(row_obj, "ipAddress", None) is not None
                    else None,

                "campaign_name":
                    str(row_obj.campaignName)
                    if getattr(row_obj, "campaignName", None) is not None
                    else None,

                "attack_vector":
                    str(row_obj.attackVector)
                    if getattr(row_obj, "attackVector", None) is not None
                    else None,

                "organization_name":
                    str(row_obj.organizationName)
                    if getattr(row_obj, "organizationName", None) is not None
                    else None,

                "industry":
                    str(row_obj.industry)
                    if getattr(row_obj, "industry", None) is not None
                    else None,
            }
        )


    return rows


# ============================================================
# 9. MALWARE RETRIEVAL
# ============================================================

def retrieve_malware_context(
    entity_id: str,
) -> list[dict[str, object]]:
    """
    Retrieve context around one Malware entity.
    """

    query = f"""
    SELECT
        ?malwareName
        ?malwareType
        ?actorName
        ?cve
        ?severity
        ?cvss
        ?domainName
        ?ipAddress

    WHERE {{

        ex:{entity_id}
            ex:malwareName
            ?malwareName .

        OPTIONAL {{
            ex:{entity_id}
                ex:malwareType
                ?malwareType .
        }}

        OPTIONAL {{

            ?actor
                ex:usesMalware
                ex:{entity_id} .

            ?actor
                ex:actorName
                ?actorName .
        }}

        OPTIONAL {{

            ex:{entity_id}
                ex:exploits
                ?vulnerability .

            ?vulnerability
                ex:cveId
                ?cve .

            OPTIONAL {{
                ?vulnerability
                    ex:severity
                    ?severity .
            }}

            OPTIONAL {{
                ?vulnerability
                    ex:cvssScore
                    ?cvss .
            }}
        }}

        OPTIONAL {{

            ex:{entity_id}
                ex:communicatesWith
                ?domain .

            ?domain
                ex:domainName
                ?domainName .

            OPTIONAL {{

                ?domain
                    ex:resolvesTo
                    ?ip .

                ?ip
                    ex:ipAddress
                    ?ipAddress .
            }}
        }}
    }}
    """


    results = graph.query(
        PREFIXES + query
    )


    rows: list[dict[str, Any]] = []


    for row in results:

        row_obj: Any = cast(Any, row)

        rows.append(
            {
                "malware_name":
                    str(row_obj.malwareName)
                    if getattr(row_obj, "malwareName", None) is not None
                    else None,

                "malware_type":
                    str(row_obj.malwareType)
                    if getattr(row_obj, "malwareType", None) is not None
                    else None,

                "associated_actor":
                    str(row_obj.actorName)
                    if getattr(row_obj, "actorName", None) is not None
                    else None,

                "cve":
                    str(row_obj.cve)
                    if getattr(row_obj, "cve", None) is not None
                    else None,

                "severity":
                    str(row_obj.severity)
                    if getattr(row_obj, "severity", None) is not None
                    else None,

                "cvss":
                    float(row_obj.cvss)
                    if getattr(row_obj, "cvss", None) is not None
                    else None,

                "domain_name":
                    str(row_obj.domainName)
                    if getattr(row_obj, "domainName", None) is not None
                    else None,

                "ip_address":
                    str(row_obj.ipAddress)
                    if getattr(row_obj, "ipAddress", None) is not None
                    else None,
            }
        )


    return rows


# ============================================================
# 10. GENERIC ENTITY CONTEXT
# ============================================================

def retrieve_generic_context(
    entity_id: str,
) -> list[dict[str, object]]:
    """
    Generic graph neighborhood retrieval.

    Useful for entities where we haven't written a
    specialized retrieval template yet.
    """

    query = f"""
    SELECT
        ?predicate
        ?object

    WHERE {{

        ex:{entity_id}
            ?predicate
            ?object .
    }}
    """


    results = graph.query(
        PREFIXES + query
    )


    rows: list[dict[str, Any]] = []


    for row in results:

        row_obj: Any = cast(Any, row)

        rows.append(
            {
                "predicate":
                    str(getattr(row_obj, "predicate", None)),

                "object":
                    str(getattr(row_obj, "object", None)),
            }
        )


    return rows


# ============================================================
# 11. ROUTE RETRIEVAL BY ENTITY TYPE
# ============================================================

def retrieve_graph_context(
    detected_entity: dict[str, object],
) -> list[dict[str, object]]:
    """
    Choose the appropriate SPARQL retrieval strategy.
    """

    entity_id = str(
        detected_entity[
            "entity_id"
        ]
    )


    entity_type = str(
        detected_entity[
            "entity_type"
        ]
    )


    if entity_type == "ThreatActor":

        return (
            retrieve_threat_actor_context(
                entity_id
            )
        )


    if entity_type == "Malware":

        return (
            retrieve_malware_context(
                entity_id
            )
        )


    return (
        retrieve_generic_context(
            entity_id
        )
    )


# ============================================================
# 12. BUILD GRAPH-RAG CONTEXT PACKAGE
# ============================================================

def build_context_package(
    question: str,
) -> dict[str, object]:
    """
    Full retrieval flow.
    """

    detected_entity = (
        detect_entity(
            question
        )
    )


    if detected_entity is None:

        return {
            "question":
                question,

            "status":
                "ENTITY_NOT_FOUND",

            "detected_entity":
                None,

            "graph_context":
                [],
        }


    graph_context = (
        retrieve_graph_context(
            detected_entity
        )
    )


    return {
        "question":
            question,

        "status":
            "SUCCESS",

        "detected_entity":
            {
                "entity_id":
                    detected_entity[
                        "entity_id"
                    ],

                "entity_name":
                    detected_entity[
                        "entity_name"
                    ],

                "entity_type":
                    detected_entity[
                        "entity_type"
                    ],
            },

        "graph_context":
            graph_context,
    }


# ============================================================
# 13. LEARNING TEST QUESTION
# ============================================================
#
# Later this will come from a user interface or CLI input.
#
# You can change this question and rerun the script.
#
# ============================================================

QUESTION = (
    "When was APT29 first discovered?"
)


parser = argparse.ArgumentParser(description="Retrieve evidence from the local Knowledge Graph.")
parser.add_argument("--question", default=QUESTION, help="Question containing a known graph entity.")
QUESTION = parser.parse_args().question # type: ignore


# ============================================================
# 14. RUN RETRIEVAL
# ============================================================

context_package = (
    build_context_package(
        QUESTION
    )
)


# ============================================================
# 15. DISPLAY RESULT
# ============================================================

print("\n")
print("=" * 80)
print("USER QUESTION")
print("=" * 80)


print(
    context_package[
        "question"
    ]
)


print("\n")
print("=" * 80)
print("ENTITY DETECTION")
print("=" * 80)


if (
    context_package[
        "detected_entity"
    ]
    is None
):

    print(
        "No known graph entity "
        "was detected."
    )

else:

    print(
        json.dumps(
            context_package[
                "detected_entity"
            ],
            indent=2,
        )
    )


print("\n")
print("=" * 80)
print("GRAPH CONTEXT")
print("=" * 80)


print(
    json.dumps(
        context_package[
            "graph_context"
        ],
        indent=2,
    )
)


# ============================================================
# 16. SAVE CONTEXT PACKAGE
# ============================================================

with open(
    OUTPUT_FILE,
    "w",
    encoding="utf-8",
) as file:

    json.dump(
        context_package,
        file,
        indent=2,
    )


print("\n")
print("=" * 80)
print("GRAPH RETRIEVAL COMPLETED")
print("=" * 80)


print(
    f"\nContext saved to:\n"
    f"{OUTPUT_FILE}"
)