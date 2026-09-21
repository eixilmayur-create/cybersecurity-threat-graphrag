# ============================================================
# STAGE 15
# GRAPH-RAG EVALUATION FRAMEWORK
# ============================================================
#
# PURPOSE
# -------
# Evaluate the Cybersecurity Graph-RAG pipeline using
# a small labeled test set.
#
# METRICS
# -------
#
# 1. Entity Resolution Accuracy
#
#    Did the pipeline detect the correct canonical entity?
#
#
# 2. Retrieval Coverage
#
#    Did the retrieved graph context contain the expected facts?
#
#
# 3. Grounded Answer Support
#
#    Does the generated answer contain facts supported by
#    the retrieved graph context?
#
#
# 4. End-to-End Success Rate
#
#    Did both entity resolution and retrieval succeed?
#
#
# IMPORTANT
# ---------
# This is a small learning evaluation set.
#
# Do NOT present these numbers as production benchmark accuracy.
#
# ============================================================


# pyright: reportUnknownMemberType=false
# pyright: reportUnknownArgumentType=false
# pyright: reportUnknownVariableType=false

from pathlib import Path
import json
import re
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
    / "evaluation"
)


OUTPUT_DIR.mkdir(
    parents=True,
    exist_ok=True,
)


DETAIL_REPORT = (
    OUTPUT_DIR
    / "graphrag_evaluation_details.csv"
)


SUMMARY_REPORT = (
    OUTPUT_DIR
    / "graphrag_evaluation_summary.csv"
)


# ============================================================
# 2. LOAD RDF GRAPH
# ============================================================

graph = Graph()


graph.parse(
    GRAPH_FILE,
    format="turtle",
)


print("=" * 80)
print("GRAPH-RAG EVALUATION FRAMEWORK")
print("=" * 80)


print(
    f"\nKnowledge Graph triples: "
    f"{len(graph)}"
)


# ============================================================
# 3. LOAD ENTITY CATALOG
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
# 4. NORMALIZATION
# ============================================================

def normalize_text(text: str | object) -> str:
    """
    Normalize text for simple entity matching.
    """

    return re.sub(
        r"[^a-z0-9]",
        "",
        str(text).lower(),
    )


# ============================================================
# 5. ENTITY DETECTION
# ============================================================

def detect_entity(question: str) -> dict[str, object] | None:
    """
    Detect the canonical graph entity mentioned in the question.
    """

    normalized_question = normalize_text(
        question
    )


    matches: list[dict[str, object]] = []


    for _, row in (
        entity_catalog_df.iterrows()
    ):

        normalized_name = normalize_text(
            row["entity_name"]
        )


        if (
            normalized_name
            and normalized_name
            in normalized_question
        ):

            matches.append(
                {
                    "entity_id":
                        row["entity_id"],

                    "entity_name":
                        row["entity_name"],

                    "entity_type":
                        row["entity_type"],

                    "length":
                        len(
                            normalized_name
                        ),
                }
            )


    if not matches:

        return None


    matches = sorted(
        matches,
        key=lambda item: int(cast(int, item["length"])),
        reverse=True,
    )


    return matches[0]


# ============================================================
# 6. GENERIC NEIGHBORHOOD RETRIEVAL
# ============================================================
#
# For evaluation we retrieve both:
#
# outgoing relationships
#
# and
#
# incoming relationships.
#
# This makes the evaluator reusable across entity types.
#
# ============================================================

PREFIXES = """
PREFIX ex: <http://example.org/cybersecurity/>
"""


def retrieve_entity_neighborhood(
    entity_id: str,
) -> list[tuple[str, str, str]]:
    """
    Retrieve the local RDF neighborhood of one entity.

    Returns human-readable strings representing graph facts.
    """

    query = f"""
    SELECT
        ?subject
        ?predicate
        ?object

    WHERE {{

        {{
            ex:{entity_id}
                ?predicate
                ?object .

            BIND(
                ex:{entity_id}
                AS ?subject
            )
        }}

        UNION

        {{
            ?subject
                ?predicate
                ex:{entity_id} .

            BIND(
                ex:{entity_id}
                AS ?object
            )
        }}
    }}
    """


    results = graph.query(
        PREFIXES + query
    )


    facts: list[tuple[str, str, str]] = []


    for row in results:

        row_obj: Any = cast(Any, row)

        facts.append(
            (
                str(getattr(row_obj, "subject", None)),
                str(getattr(row_obj, "predicate", None)),
                str(getattr(row_obj, "object", None)),
            )
        )


    return facts


# ============================================================
# 7. MULTI-HOP THREAT ACTOR RETRIEVAL
# ============================================================

def retrieve_actor_context(
    entity_id: str,
) -> list[dict[str, str | None]]:
    """
    Retrieve the major threat-investigation paths
    for a ThreatActor.
    """

    query = f"""
    PREFIX ex: <http://example.org/cybersecurity/>

    SELECT
        ?actorName
        ?malwareName
        ?cve
        ?domainName
        ?ipAddress
        ?campaignName
        ?organizationName

    WHERE {{

        ex:{entity_id}
            ex:actorName
            ?actorName .

        OPTIONAL {{

            ex:{entity_id}
                ex:usesMalware
                ?malware .

            ?malware
                ex:malwareName
                ?malwareName .

            OPTIONAL {{

                ?malware
                    ex:exploits
                    ?vulnerability .

                ?vulnerability
                    ex:cveId
                    ?cve .
            }}

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

        OPTIONAL {{

            ex:{entity_id}
                ex:attributedToCampaign
                ?campaign .

            ?campaign
                ex:campaignName
                ?campaignName .

            OPTIONAL {{

                ?campaign
                    ex:targets
                    ?organization .

                ?organization
                    ex:organizationName
                    ?organizationName .
            }}
        }}
    }}
    """


    results = graph.query(
        query
    )


    rows: list[dict[str, str | None]] = []


    for row in results:

        row_obj: Any = cast(Any, row)

        rows.append(
            {
                "actor_name":
                    str(getattr(row_obj, "actorName", None))
                    if getattr(row_obj, "actorName", None) is not None
                    else None,

                "malware_name":
                    str(getattr(row_obj, "malwareName", None))
                    if getattr(row_obj, "malwareName", None) is not None
                    else None,

                "cve":
                    str(getattr(row_obj, "cve", None))
                    if getattr(row_obj, "cve", None) is not None
                    else None,

                "domain_name":
                    str(getattr(row_obj, "domainName", None))
                    if getattr(row_obj, "domainName", None) is not None
                    else None,

                "ip_address":
                    str(getattr(row_obj, "ipAddress", None))
                    if getattr(row_obj, "ipAddress", None) is not None
                    else None,

                "campaign_name":
                    str(getattr(row_obj, "campaignName", None))
                    if getattr(row_obj, "campaignName", None) is not None
                    else None,

                "organization_name":
                    str(getattr(row_obj, "organizationName", None))
                    if getattr(row_obj, "organizationName", None) is not None
                    else None,
            }
        )


    return rows


# ============================================================
# 8. MALWARE RETRIEVAL
# ============================================================

def retrieve_malware_context(
    entity_id: str,
) -> list[dict[str, str | None]]:

    query = f"""
    PREFIX ex: <http://example.org/cybersecurity/>

    SELECT
        ?malwareName
        ?actorName
        ?cve
        ?domainName
        ?ipAddress

    WHERE {{

        ex:{entity_id}
            ex:malwareName
            ?malwareName .

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
        query
    )


    rows: list[dict[str, str | None]] = []


    for row in results:

        row_obj: Any = cast(Any, row)

        rows.append(
            {
                "malware_name":
                    str(getattr(row_obj, "malwareName", None))
                    if getattr(row_obj, "malwareName", None) is not None
                    else None,

                "actor_name":
                    str(getattr(row_obj, "actorName", None))
                    if getattr(row_obj, "actorName", None) is not None
                    else None,

                "cve":
                    str(getattr(row_obj, "cve", None))
                    if getattr(row_obj, "cve", None) is not None
                    else None,

                "domain_name":
                    str(getattr(row_obj, "domainName", None))
                    if getattr(row_obj, "domainName", None) is not None
                    else None,

                "ip_address":
                    str(getattr(row_obj, "ipAddress", None))
                    if getattr(row_obj, "ipAddress", None) is not None
                    else None,
            }
        )


    return rows


# ============================================================
# 9. ROUTE RETRIEVAL
# ============================================================

def retrieve_context(
    detected_entity: dict[str, object],
) -> list[dict[str, str | None]] | list[tuple[str, str, str]]:

    entity_type = str(
        detected_entity[
            "entity_type"
        ]
    )


    entity_id = str(
        detected_entity[
            "entity_id"
        ]
    )


    if entity_type == "ThreatActor":

        return retrieve_actor_context(
            entity_id
        )


    if entity_type == "Malware":

        return retrieve_malware_context(
            entity_id
        )


    return retrieve_entity_neighborhood(
        entity_id
    )


# ============================================================
# 10. LABELED EVALUATION SET
# ============================================================
#
# expected_facts are strings that SHOULD appear somewhere
# inside the retrieved graph context.
#
# ============================================================

EVALUATION_SET = [

    {
        "question":
            "What malware and vulnerability are associated with APT29?",

        "expected_entity_id":
            "TA001",

        "expected_facts": [
            "SolarDrop",
            "CVE-2026-1001",
        ],
    },


    {
        "question":
            "What infrastructure is connected to APT-29?",

        "expected_entity_id":
            "TA001",

        "expected_facts": [
            "secure-update-example.com",
            "192.0.2.10",
        ],
    },


    {
        "question":
            "Which campaign is associated with APT29?",

        "expected_entity_id":
            "TA001",

        "expected_facts": [
            "Operation Nightfall",
        ],
    },


    {
        "question":
            "What organization is targeted by Operation Black Ice?",

        "expected_entity_id":
            "CAM002",

        "expected_facts": [
            "ORG002",
        ],
    },


    {
        "question":
            "What vulnerability is connected to SolarDrop?",

        "expected_entity_id":
            "MAL001",

        "expected_facts": [
            "CVE-2026-1001",
        ],
    },


    {
        "question":
            "What IP address is connected to SolarDrop?",

        "expected_entity_id":
            "MAL001",

        "expected_facts": [
            "192.0.2.10",
        ],
    },


    {
        "question":
            "Which threat actor uses BlackCrypt?",

        "expected_entity_id":
            "MAL002",

        "expected_facts": [
            "Shadow Spider",
        ],
    },


    {
        "question":
            "What campaign is associated with Crimson Fox?",

        "expected_entity_id":
            "TA003",

        "expected_facts": [
            "Operation Silent Web",
        ],
    },


    {
        "question":
            "What infrastructure is connected to HydraBot?",

        "expected_entity_id":
            "MAL005",

        "expected_facts": [
            "software-update-example.org",
            "203.0.113.50",
        ],
    },


    {
        "question":
            "What campaign is associated with Silent Raven?",

        "expected_entity_id":
            "TA004",

        "expected_facts": [
            "Operation Red Cloud",
        ],
    },
]


# ============================================================
# 11. HELPER: FLATTEN RETRIEVED CONTEXT
# ============================================================

def context_to_text(context: list[dict[str, str | None]] | list[tuple[str, str, str]]) -> str:
    """
    Convert graph retrieval output into a searchable string.
    """

    return json.dumps(
        context,
        ensure_ascii=False,
    ).lower()


# ============================================================
# 12. RUN EVALUATION
# ============================================================

evaluation_results = []


for test_number, test_case in enumerate(
    EVALUATION_SET,
    start=1,
):

    question = (
        test_case[
            "question"
        ]
    )


    expected_entity_id = (
        test_case[
            "expected_entity_id"
        ]
    )


    expected_facts = (
        test_case[
            "expected_facts"
        ]
    )


    # --------------------------------------------------------
    # ENTITY RESOLUTION
    # --------------------------------------------------------

    detected_entity = detect_entity(
        question
    )


    if detected_entity:

        detected_entity_id = (
            detected_entity[
                "entity_id"
            ]
        )

    else:

        detected_entity_id = None


    entity_correct = (
        detected_entity_id
        == expected_entity_id
    )


    # --------------------------------------------------------
    # GRAPH RETRIEVAL
    # --------------------------------------------------------

    if detected_entity:

        retrieved_context = (
            retrieve_context(
                detected_entity
            )
        )

    else:

        retrieved_context = []


    context_text = context_to_text(
        retrieved_context
    )


    # --------------------------------------------------------
    # FACT COVERAGE
    # --------------------------------------------------------

    matched_facts = []


    missing_facts = []


    for expected_fact in (
        expected_facts
    ):

        if (
            expected_fact.lower()
            in context_text
        ):

            matched_facts.append(
                expected_fact
            )

        else:

            missing_facts.append(
                expected_fact
            )


    total_expected_facts = len(
        expected_facts
    )


    matched_count = len(
        matched_facts
    )


    retrieval_coverage = (
        matched_count
        / total_expected_facts
        if total_expected_facts > 0
        else 0
    )


    retrieval_success = (
        retrieval_coverage == 1.0
    )


    # --------------------------------------------------------
    # END-TO-END SUCCESS
    # --------------------------------------------------------

    end_to_end_success = (
        entity_correct
        and retrieval_success
    )


    evaluation_results.append(
        {
            "test_id":
                test_number,

            "question":
                question,

            "expected_entity_id":
                expected_entity_id,

            "detected_entity_id":
                detected_entity_id,

            "entity_resolution_correct":
                entity_correct,

            "expected_facts":
                " | ".join(
                    expected_facts
                ),

            "matched_facts":
                " | ".join(
                    matched_facts
                ),

            "missing_facts":
                " | ".join(
                    missing_facts
                ),

            "retrieval_coverage":
                round(
                    retrieval_coverage,
                    4,
                ),

            "retrieval_success":
                retrieval_success,

            "end_to_end_success":
                end_to_end_success,
        }
    )


# ============================================================
# 13. CREATE DETAIL DATAFRAME
# ============================================================

results_df = pd.DataFrame(
    evaluation_results
)


# ============================================================
# 14. CALCULATE METRICS
# ============================================================

total_tests = len(
    results_df
)


entity_accuracy = (
    results_df[
        "entity_resolution_correct"
    ]
    .mean()
    * 100
)


average_retrieval_coverage = (
    results_df[
        "retrieval_coverage"
    ]
    .mean()
    * 100
)


retrieval_success_rate = (
    results_df[
        "retrieval_success"
    ]
    .mean()
    * 100
)


end_to_end_success_rate = (
    results_df[
        "end_to_end_success"
    ]
    .mean()
    * 100
)


# ============================================================
# 15. CREATE SUMMARY
# ============================================================

summary_df = pd.DataFrame(
    [
        {
            "total_test_questions":
                total_tests,

            "entity_resolution_accuracy_percent":
                round(
                    entity_accuracy,
                    2,
                ),

            "average_retrieval_coverage_percent":
                round(
                    average_retrieval_coverage,
                    2,
                ),

            "retrieval_success_rate_percent":
                round(
                    retrieval_success_rate,
                    2,
                ),

            "end_to_end_success_rate_percent":
                round(
                    end_to_end_success_rate,
                    2,
                ),
        }
    ]
)


# ============================================================
# 16. SAVE REPORTS
# ============================================================

results_df.to_csv(
    DETAIL_REPORT,
    index=False,
)


summary_df.to_csv(
    SUMMARY_REPORT,
    index=False,
)


# ============================================================
# 17. DISPLAY DETAILS
# ============================================================

print("\n")
print("=" * 80)
print("EVALUATION RESULTS")
print("=" * 80)


for _, row in results_df.iterrows():

    print("\n" + "-" * 80)

    print(
        f"Test: "
        f"{row['test_id']}"
    )

    print(
        f"Question: "
        f"{row['question']}"
    )

    print(
        f"Expected Entity: "
        f"{row['expected_entity_id']}"
    )

    print(
        f"Detected Entity: "
        f"{row['detected_entity_id']}"
    )

    print(
        f"Entity Correct: "
        f"{row['entity_resolution_correct']}"
    )

    print(
        f"Retrieval Coverage: "
        f"{row['retrieval_coverage'] * 100:.2f}%"
    )

    print(
        f"End-to-End Success: "
        f"{row['end_to_end_success']}"
    )


# ============================================================
# 18. DISPLAY SUMMARY
# ============================================================

print("\n")
print("=" * 80)
print("GRAPH-RAG EVALUATION SUMMARY")
print("=" * 80)


print(
    f"\nTest Questions: "
    f"{total_tests}"
)


print(
    f"Entity Resolution Accuracy: "
    f"{entity_accuracy:.2f}%"
)


print(
    f"Average Retrieval Coverage: "
    f"{average_retrieval_coverage:.2f}%"
)


print(
    f"Retrieval Success Rate: "
    f"{retrieval_success_rate:.2f}%"
)


print(
    f"End-to-End Success Rate: "
    f"{end_to_end_success_rate:.2f}%"
)


print(
    f"\nDetailed report:\n"
    f"{DETAIL_REPORT}"
)


print(
    f"\nSummary report:\n"
    f"{SUMMARY_REPORT}"
)


print("\n")
print("=" * 80)
print("GRAPH-RAG EVALUATION COMPLETED")
print("=" * 80)