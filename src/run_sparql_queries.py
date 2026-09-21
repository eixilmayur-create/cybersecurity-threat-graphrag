# ============================================================
# STAGE 6
# SPARQL QUERYING + MULTI-HOP THREAT INVESTIGATION
# ============================================================
#
# PURPOSE
# -------
# This script loads our RDF Knowledge Graph and runs
# multiple SPARQL queries.
#
# 1. Basic entity retrieval
# 2. Threat Actor -> Malware
# 3. Threat Actor -> Malware -> Vulnerability
# 4. Threat Actor -> Campaign -> Organization
# 5. Threat Actor -> Malware -> Domain -> IP Address
# 6. Combined multi-hop threat investigation
#
# These queries later become the retrieval layer
# for Graph-RAG.
#
# ============================================================


from pathlib import Path
from typing import Iterable, cast

from rdflib import Graph


# ============================================================
# 1. PROJECT PATH
# ============================================================

PROJECT_ROOT = Path(__file__).resolve().parent.parent

GRAPH_FILE = (
    PROJECT_ROOT
    / "data"
    / "rdf"
    / "cybersecurity_knowledge_graph.ttl"
)


# ============================================================
# 2. LOAD RDF GRAPH
# ============================================================

graph = Graph()

print("=" * 75)
print("CYBERSECURITY SPARQL QUERY DEMONSTRATION")
print("=" * 75)

print(f"\nLoading Knowledge Graph:\n{GRAPH_FILE}")

graph.parse(
    GRAPH_FILE,
    format="turtle",
)

print(
    f"\nTotal triples loaded: {len(graph)}"
)


# ============================================================
# 3. PREFIXES
# ============================================================

PREFIXES = """
PREFIX ex: <http://example.org/cybersecurity/>
PREFIX rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#>
"""


# ============================================================
# 4. HELPER FUNCTION TO RUN QUERIES
# ============================================================

def run_query(title: str, query: str) -> None:
    """
    Run one SPARQL query and print the results.

    Parameters
    ----------
    title:
        Human-readable query title.

    query:
        SPARQL SELECT query.
    """

    print("\n")
    print("=" * 75)
    print(title)
    print("=" * 75)

    results = graph.query(
        PREFIXES + query
    )

    # Display result column names.
    headers = [
        str(variable)
        for variable in (results.vars or [])
    ]

    print(" | ".join(headers))
    print("-" * 75)

    row_count = 0

    for row in results:

        values = [
            str(value)
            if value is not None
            else ""
            for value in cast(Iterable[object], row)
        ]

        print(
            " | ".join(values)
        )

        row_count += 1

    print(
        f"\nRows returned: {row_count}"
    )


# ============================================================
# QUERY 1
# LIST ALL THREAT ACTORS
# ============================================================

query_1 = """
SELECT ?actor ?actorName ?actorType
WHERE {

    ?actor rdf:type ex:ThreatActor .

    ?actor ex:actorName ?actorName .

    ?actor ex:actorType ?actorType .
}
ORDER BY ?actorName
"""


run_query(
    "QUERY 1 - ALL THREAT ACTORS",
    query_1,
)


# ============================================================
# QUERY 2
# THREAT ACTOR -> MALWARE
# ============================================================

query_2 = """
SELECT
    ?actorName
    ?malwareName
    ?malwareType
WHERE {

    ?actor rdf:type ex:ThreatActor .

    ?actor ex:actorName ?actorName .

    ?actor ex:usesMalware ?malware .

    ?malware ex:malwareName ?malwareName .

    ?malware ex:malwareType ?malwareType .
}
ORDER BY ?actorName
"""


run_query(
    "QUERY 2 - THREAT ACTOR TO MALWARE",
    query_2,
)


# ============================================================
# QUERY 3
# MULTI-HOP:
#
# Threat Actor
#      ->
# Malware
#      ->
# Vulnerability
#
# ============================================================

query_3 = """
SELECT
    ?actorName
    ?malwareName
    ?cve
    ?severity
    ?cvss
WHERE {

    ?actor rdf:type ex:ThreatActor .

    ?actor ex:actorName ?actorName .

    ?actor ex:usesMalware ?malware .

    ?malware ex:malwareName ?malwareName .

    ?malware ex:exploits ?vulnerability .

    ?vulnerability ex:cveId ?cve .

    ?vulnerability ex:severity ?severity .

    ?vulnerability ex:cvssScore ?cvss .
}
ORDER BY DESC(?cvss)
"""


run_query(
    "QUERY 3 - ACTOR -> MALWARE -> VULNERABILITY",
    query_3,
)


# ============================================================
# QUERY 4
# MULTI-HOP:
#
# Threat Actor
#      ->
# Campaign
#      ->
# Organization
#
# ============================================================

query_4 = """
SELECT
    ?actorName
    ?campaignName
    ?attackVector
    ?organizationName
    ?industry
WHERE {

    ?actor rdf:type ex:ThreatActor .

    ?actor ex:actorName ?actorName .

    ?actor ex:attributedToCampaign ?campaign .

    ?campaign ex:campaignName ?campaignName .

    ?campaign ex:attackVector ?attackVector .

    ?campaign ex:targets ?organization .

    ?organization ex:organizationName ?organizationName .

    ?organization ex:industry ?industry .
}
ORDER BY ?actorName
"""


run_query(
    "QUERY 4 - ACTOR -> CAMPAIGN -> ORGANIZATION",
    query_4,
)


# ============================================================
# QUERY 5
# MULTI-HOP INFRASTRUCTURE TRAVERSAL:
#
# Threat Actor
#      ->
# Malware
#      ->
# Domain
#      ->
# IP Address
#
# ============================================================

query_5 = """
SELECT
    ?actorName
    ?malwareName
    ?domainName
    ?ipAddress
WHERE {

    ?actor rdf:type ex:ThreatActor .

    ?actor ex:actorName ?actorName .

    ?actor ex:usesMalware ?malware .

    ?malware ex:malwareName ?malwareName .

    ?malware ex:communicatesWith ?domain .

    ?domain ex:domainName ?domainName .

    ?domain ex:resolvesTo ?ip .

    ?ip ex:ipAddress ?ipAddress .
}
ORDER BY ?actorName
"""


run_query(
    "QUERY 5 - ACTOR -> MALWARE -> DOMAIN -> IP",
    query_5,
)


# ============================================================
# QUERY 6
# FILTER FOR HIGH-SEVERITY VULNERABILITIES
#
# Threat Actor
#     ->
# Malware
#     ->
# Vulnerability
#
# We only return CVSS >= 9.
#
# ============================================================

query_6 = """
SELECT
    ?actorName
    ?malwareName
    ?cve
    ?severity
    ?cvss
WHERE {

    ?actor ex:actorName ?actorName .

    ?actor ex:usesMalware ?malware .

    ?malware ex:malwareName ?malwareName .

    ?malware ex:exploits ?vulnerability .

    ?vulnerability ex:cveId ?cve .

    ?vulnerability ex:severity ?severity .

    ?vulnerability ex:cvssScore ?cvss .

    FILTER(?cvss >= 9.0)
}
ORDER BY DESC(?cvss)
"""


run_query(
    "QUERY 6 - CRITICAL / HIGH-RISK EXPLOIT PATHS",
    query_6,
)


# ============================================================
# QUERY 7
# COMBINED MULTI-HOP THREAT INVESTIGATION
#
# This connects both sides of the threat actor:
#
#
# Vulnerability
#      ^
#      |
#   Malware
#      ^
#      |
# Threat Actor
#      |
#      v
#   Campaign
#      |
#      v
# Organization
#
#
# This is a very important Graph-RAG query.
#
# ============================================================

query_7 = """
SELECT
    ?actorName
    ?malwareName
    ?cve
    ?cvss
    ?campaignName
    ?organizationName
    ?industry
WHERE {

    ?actor rdf:type ex:ThreatActor .

    ?actor ex:actorName ?actorName .


    # Actor -> Malware

    ?actor ex:usesMalware ?malware .

    ?malware ex:malwareName ?malwareName .


    # Malware -> Vulnerability

    ?malware ex:exploits ?vulnerability .

    ?vulnerability ex:cveId ?cve .

    ?vulnerability ex:cvssScore ?cvss .


    # Actor -> Campaign

    ?actor ex:attributedToCampaign ?campaign .

    ?campaign ex:campaignName ?campaignName .


    # Campaign -> Organization

    ?campaign ex:targets ?organization .

    ?organization ex:organizationName ?organizationName .

    ?organization ex:industry ?industry .
}
ORDER BY DESC(?cvss)
"""


run_query(
    "QUERY 7 - COMBINED MULTI-HOP THREAT INVESTIGATION",
    query_7,
)


# ============================================================
# QUERY 8
# FULL THREAT INVESTIGATION:
#
# Threat Actor
#   |
#   +--> Malware
#   |      |
#   |      +--> Vulnerability
#   |
#   |      +--> Domain
#   |              |
#   |              +--> IP
#   |
#   +--> Campaign
#           |
#           +--> Organization
#
# ============================================================

query_8 = """
SELECT
    ?actorName
    ?malwareName
    ?cve
    ?cvss
    ?domainName
    ?ipAddress
    ?campaignName
    ?organizationName
WHERE {

    ?actor rdf:type ex:ThreatActor .

    ?actor ex:actorName ?actorName .


    # ========================================
    # ACTOR -> MALWARE
    # ========================================

    ?actor ex:usesMalware ?malware .

    ?malware ex:malwareName ?malwareName .


    # ========================================
    # MALWARE -> VULNERABILITY
    # ========================================

    ?malware ex:exploits ?vulnerability .

    ?vulnerability ex:cveId ?cve .

    ?vulnerability ex:cvssScore ?cvss .


    # ========================================
    # MALWARE -> DOMAIN -> IP
    # ========================================

    ?malware ex:communicatesWith ?domain .

    ?domain ex:domainName ?domainName .

    ?domain ex:resolvesTo ?ip .

    ?ip ex:ipAddress ?ipAddress .


    # ========================================
    # ACTOR -> CAMPAIGN -> ORGANIZATION
    # ========================================

    ?actor ex:attributedToCampaign ?campaign .

    ?campaign ex:campaignName ?campaignName .

    ?campaign ex:targets ?organization .

    ?organization ex:organizationName ?organizationName .
}
ORDER BY ?actorName
"""


run_query(
    "QUERY 8 - FULL MULTI-HOP THREAT INVESTIGATION",
    query_8,
)


# ============================================================
# FINAL MESSAGE
# ============================================================

print("\n")
print("=" * 75)
print("ALL SPARQL QUERIES COMPLETED SUCCESSFULLY")
print("=" * 75)