# ============================================================
# STAGE 16
# FASTAPI DEPLOYMENT LAYER
# ============================================================
#
# PURPOSE
# -------
# Expose the Cybersecurity Graph-RAG project through HTTP APIs.
#
# ENDPOINTS
# ---------
#
# GET  /health
#      Check whether the service is running.
#
# GET  /entity/{entity_name}
#      Resolve an entity name to a canonical graph entity.
#
# POST /retrieve
#      Retrieve structured multi-hop graph context.
#
# POST /ask
#      Run the complete Graph-RAG pipeline:
#
#      Question
#          ↓
#      Entity Detection
#          ↓
#      SPARQL Retrieval
#          ↓
#      Gemini
#          ↓
#      Grounded Answer
#
# ============================================================


# pyright: reportUnknownMemberType=false
# pyright: reportUnknownArgumentType=false
# pyright: reportUnknownVariableType=false

from pathlib import Path
from typing import Any, Literal, cast
import os
import re

import pandas as pd

from dotenv import load_dotenv

from fastapi import (
    FastAPI,
    HTTPException,
)

from pydantic import (
    BaseModel,
    Field,
)

from rdflib import Graph

from google import genai
from google.genai import types


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


# ============================================================
# 2. LOAD ENVIRONMENT VARIABLES
# ============================================================

load_dotenv(
    PROJECT_ROOT / ".env",
    override=True,
)


GEMINI_API_KEY = os.getenv(
    "GEMINI_API_KEY"
)


if not GEMINI_API_KEY:

    raise RuntimeError(
        "GEMINI_API_KEY was not found in .env"
    )


# ============================================================
# 3. CONFIGURATION
# ============================================================

MODEL_NAME = "gemini-2.5-flash-lite"


# ============================================================
# 4. CREATE FASTAPI APPLICATION
# ============================================================

app = FastAPI(

    title=(
        "Cybersecurity Threat Intelligence Graph-RAG API"
    ),

    description=(
        "Knowledge Graph + SPARQL + Gemini API for "
        "multi-hop cybersecurity threat intelligence retrieval."
    ),

    version="1.0.0",
)


# ============================================================
# 5. CREATE GEMINI CLIENT
# ============================================================

gemini_client = genai.Client(
    api_key=GEMINI_API_KEY
)


# ============================================================
# 6. LOAD RDF KNOWLEDGE GRAPH
# ============================================================

graph = Graph()


graph.parse(
    GRAPH_FILE,
    format="turtle",
)


# ============================================================
# 7. LOAD ENTITY DATA
# ============================================================

threat_actors = pd.read_csv(
    RAW_DATA_DIR / "threat_actors.csv"
)

malware = pd.read_csv(
    RAW_DATA_DIR / "malware.csv"
)

campaigns = pd.read_csv(
    RAW_DATA_DIR / "campaigns.csv"
)

organizations = pd.read_csv(
    RAW_DATA_DIR / "organizations.csv"
)

domains = pd.read_csv(
    RAW_DATA_DIR / "domains.csv"
)

vulnerabilities = pd.read_csv(
    RAW_DATA_DIR / "vulnerabilities.csv"
)


# ============================================================
# 8. BUILD ENTITY CATALOG
# ============================================================

entity_catalog: list[dict[str, str | object]] = []


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
# 9. REQUEST / RESPONSE MODELS
# ============================================================

class QuestionRequest(BaseModel):

    question: str = Field(
        min_length=3,
        description=(
            "Natural-language cybersecurity question."
        )
    )


class EntityResponse(BaseModel):

    entity_id: str
    entity_name: str
    entity_type: str


class RetrievalResponse(BaseModel):

    question: str

    status: Literal[
        "SUCCESS",
        "ENTITY_NOT_FOUND",
        "NO_CONTEXT",
    ]

    detected_entity: (
        EntityResponse
        | None
    )

    graph_context: list[dict[str, object]]


class GraphRAGAnswer(BaseModel):

    answer: str

    evidence: list[str]

    entities_used: list[str]

    confidence: float = Field(
        ge=0.0,
        le=1.0,
    )

    evidence_status: Literal[
        "SUFFICIENT",
        "PARTIAL",
        "INSUFFICIENT",
    ]


class AskResponse(BaseModel):

    question: str

    detected_entity: (
        EntityResponse
        | None
    )

    answer: str

    evidence: list[str]

    entities_used: list[str]

    confidence: float

    evidence_status: str


# ============================================================
# 10. TEXT NORMALIZATION
# ============================================================

def normalize_text(text: str | object) -> str:
    """
    Normalize names so variations such as:

    APT-29
    APT29
    APT 29

    become comparable.
    """

    return re.sub(
        r"[^a-z0-9]",
        "",
        str(text).lower(),
    )


# ============================================================
# 11. ENTITY RESOLUTION
# ============================================================

def detect_entity(
    text: str,
) -> dict[str, str] | None:
    """
    Find the best matching canonical graph entity.
    """

    normalized_text = normalize_text(
        text
    )


    matches: list[dict[str, object]] = []


    for _, row in (
        entity_catalog_df.iterrows()
    ):

        entity_name = str(row["entity_name"])
        normalized_name = normalize_text(entity_name)

        if (
            normalized_name
            and normalized_name
            in normalized_text
        ):

            matches.append(
                {
                    "entity_id": str(row["entity_id"]),
                    "entity_name": entity_name,
                    "entity_type": str(row["entity_type"]),
                    "name_length": len(normalized_name),
                }
            )


    if not matches:

        return None


    matches.sort(
        key=lambda item: cast(int, item["name_length"]),
        reverse=True,
    )


    best_match: dict[str, object] = matches[0]


    return {
        "entity_id":
            str(best_match["entity_id"]),

        "entity_name":
            str(best_match["entity_name"]),

        "entity_type":
            str(best_match["entity_type"]),
    }

# ============================================================
# 12. SPARQL PREFIXES
# ============================================================

PREFIXES = """
PREFIX ex: <http://example.org/cybersecurity/>
PREFIX rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#>
"""


# ============================================================
# 13. THREAT ACTOR RETRIEVAL
# ============================================================

def retrieve_threat_actor_context(
    entity_id: str,
) -> list[dict[str, object]]:

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


    context: list[dict[str, object]] = []


    for row in results:

        row_obj: Any = cast(Any, row)
        cvss_value = getattr(row_obj, "cvss", None)

        context.append(
            {
                "actor_name":
                    str(getattr(row_obj, "actorName", None))
                    if getattr(row_obj, "actorName", None) is not None
                    else None,

                "actor_type":
                    str(getattr(row_obj, "actorType", None))
                    if getattr(row_obj, "actorType", None) is not None
                    else None,

                "primary_motivation":
                    str(getattr(row_obj, "motivation", None))
                    if getattr(row_obj, "motivation", None) is not None
                    else None,

                "malware_name":
                    str(getattr(row_obj, "malwareName", None))
                    if getattr(row_obj, "malwareName", None) is not None
                    else None,

                "malware_type":
                    str(getattr(row_obj, "malwareType", None))
                    if getattr(row_obj, "malwareType", None) is not None
                    else None,

                "cve":
                    str(getattr(row_obj, "cve", None))
                    if getattr(row_obj, "cve", None) is not None
                    else None,

                "severity":
                    str(getattr(row_obj, "severity", None))
                    if getattr(row_obj, "severity", None) is not None
                    else None,

                "cvss":
                    float(cvss_value)
                    if cvss_value is not None and str(cvss_value).strip() != ""
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

                "attack_vector":
                    str(getattr(row_obj, "attackVector", None))
                    if getattr(row_obj, "attackVector", None) is not None
                    else None,

                "organization_name":
                    str(getattr(row_obj, "organizationName", None))
                    if getattr(row_obj, "organizationName", None) is not None
                    else None,

                "industry":
                    str(getattr(row_obj, "industry", None))
                    if getattr(row_obj, "industry", None) is not None
                    else None,
            }
        )


    return context


# ============================================================
# 14. MALWARE RETRIEVAL
# ============================================================

def retrieve_malware_context(
    entity_id: str,
) -> list[dict[str, object]]:

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


    context: list[dict[str, object]] = []


    for row in results:

        row_obj: Any = cast(Any, row)
        cvss_value = getattr(row_obj, "cvss", None)

        context.append(
            {
                "malware_name":
                    str(getattr(row_obj, "malwareName", None))
                    if getattr(row_obj, "malwareName", None) is not None
                    else None,

                "malware_type":
                    str(getattr(row_obj, "malwareType", None))
                    if getattr(row_obj, "malwareType", None) is not None
                    else None,

                "associated_actor":
                    str(getattr(row_obj, "actorName", None))
                    if getattr(row_obj, "actorName", None) is not None
                    else None,

                "cve":
                    str(getattr(row_obj, "cve", None))
                    if getattr(row_obj, "cve", None) is not None
                    else None,

                "severity":
                    str(getattr(row_obj, "severity", None))
                    if getattr(row_obj, "severity", None) is not None
                    else None,

                "cvss":
                    float(cvss_value)
                    if cvss_value is not None and str(cvss_value).strip() != ""
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


    return context


# ============================================================
# 15. GENERIC GRAPH RETRIEVAL
# ============================================================

def retrieve_generic_context(
    entity_id: str,
) -> list[dict[str, str]]:

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


    context: list[dict[str, str]] = []


    for row in results:

        row_obj: Any = cast(Any, row)

        context.append(
            {
                "predicate":
                    str(getattr(row_obj, "predicate", None)),

                "object":
                    str(getattr(row_obj, "object", None)),
            }
        )


    return context


# ============================================================
# 16. RETRIEVAL ROUTER
# ============================================================

def retrieve_context(
    detected_entity: dict[str, str],
) -> list[dict[str, object]] | list[dict[str, str]]:

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

        return retrieve_threat_actor_context(
            entity_id
        )


    if entity_type == "Malware":

        return retrieve_malware_context(
            entity_id
        )


    return retrieve_generic_context(
        entity_id
    )


# ============================================================
# 17. FULL RETRIEVAL PIPELINE
# ============================================================

def build_context(
    question: str,
) -> dict[str, object]:

    detected_entity = detect_entity(
        question
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


    context = retrieve_context(
        detected_entity
    )


    if not context:

        return {

            "question":
                question,

            "status":
                "NO_CONTEXT",

            "detected_entity":
                detected_entity,

            "graph_context":
                [],
        }


    return {

        "question":
            question,

        "status":
            "SUCCESS",

        "detected_entity":
            detected_entity,

        "graph_context":
            context,
    }


# ============================================================
# 18. GEMINI GRAPH-RAG GENERATION
# ============================================================

def generate_answer(
    question: str,
    detected_entity: dict[str, str],
    graph_context: list[dict[str, object]],
) -> GraphRAGAnswer:

    prompt = (
        "You are a cybersecurity Graph-RAG assistant.\n\n"
        "Answer the user's question using ONLY the supplied\n"
        "Knowledge Graph context.\n\n"
        "Rules:\n\n"
        "1. Do not use external knowledge.\n"
        "2. Do not invent entities or relationships.\n"
        "3. Evidence must come directly from the supplied context.\n"
        "4. If evidence is incomplete, return PARTIAL.\n"
        "5. If evidence cannot answer the question, return INSUFFICIENT.\n"
        "6. Keep the answer concise.\n"
        "7. Confidence reflects evidence completeness.\n\n"
        f"USER QUESTION:\n{question}\n\n"
        f"DETECTED ENTITY:\n{detected_entity}\n\n"
        f"GRAPH CONTEXT:\n{graph_context}\n"
    )


    try:

        response = (
            gemini_client.models.generate_content(

                model=MODEL_NAME,

                contents=prompt,

                config=types.GenerateContentConfig(

                    response_mime_type=(
                        "application/json"
                    ),

                    response_schema=(
                        GraphRAGAnswer
                    ),

                    temperature=0.0,
                ),
            )
        )


        parsed_response = response.parsed

        if parsed_response is not None:

            if isinstance(parsed_response, GraphRAGAnswer):
                return parsed_response

            return GraphRAGAnswer.model_validate(parsed_response)

        response_text = response.text

        if response_text is None:
            raise ValueError("Gemini response is empty.")

        return GraphRAGAnswer.model_validate_json(response_text)


    except Exception as error:

        raise HTTPException(

            status_code=502,

            detail=(
                "Gemini answer generation failed: "
                f"{type(error).__name__}"
            ),
        )


# ============================================================
# 19. ROOT ENDPOINT
# ============================================================

@app.get("/")
def root() -> dict[str, str]:

    return {
        "service":
            (
                "Cybersecurity Threat Intelligence "
                "Graph-RAG API"
            ),

        "version":
            "1.0.0",

        "docs":
            "/docs",
    }


# ============================================================
# 20. HEALTH ENDPOINT
# ============================================================

@app.get("/health")
def health() -> dict[str, bool | int | str]:

    return {

        "status":
            "healthy",

        "graph_loaded":
            True,

        "graph_triples":
            len(graph),

        "gemini_configured":
            bool(
                GEMINI_API_KEY
            ),
    }


# ============================================================
# 21. ENTITY ENDPOINT
# ============================================================

@app.get(
    "/entity/{entity_name}",
    response_model=EntityResponse,
)
def resolve_entity(
    entity_name: str,
):

    entity = detect_entity(
        entity_name
    )


    if entity is None:

        raise HTTPException(

            status_code=404,

            detail=(
                "Entity not found in the "
                "Knowledge Graph catalog."
            ),
        )


    return entity


# ============================================================
# 22. RETRIEVAL ENDPOINT
# ============================================================

@app.post(
    "/retrieve",
    response_model=RetrievalResponse,
)
def retrieve(
    request: QuestionRequest,
):

    result = build_context(
        request.question
    )


    return result


# ============================================================
# 23. FULL GRAPH-RAG ENDPOINT
# ============================================================

@app.post(
    "/ask",
    response_model=AskResponse,
)
def ask(
    request: QuestionRequest,
):

    retrieval = build_context(
        request.question
    )

    status = cast(str | None, retrieval.get("status"))
    detected_entity = cast(dict[str, str] | None, retrieval.get("detected_entity"))
    graph_context = cast(list[dict[str, object]], retrieval.get("graph_context", []))


    if status != "SUCCESS" or detected_entity is None:

        return AskResponse(

            question=
                request.question,

            detected_entity=None,

            answer=(
                "The Knowledge Graph does not "
                "contain enough retrieved evidence "
                "to answer this question."
            ),

            evidence=[],

            entities_used=[],

            confidence=0.0,

            evidence_status=(
                "INSUFFICIENT"
            ),
        )


    answer = generate_answer(

        request.question,

        detected_entity,

        graph_context,
    )


    return AskResponse(

        question=
            request.question,

        detected_entity=(
            EntityResponse(**detected_entity)
        ),

        answer=
            answer.answer,

        evidence=
            answer.evidence,

        entities_used=
            answer.entities_used,

        confidence=
            answer.confidence,

        evidence_status=
            answer.evidence_status,
    )