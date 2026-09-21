# ============================================================
# CREATE INTENTIONALLY INVALID CYBERSECURITY GRAPH
# ============================================================
#
# PURPOSE
# -------
# Produce a copy of the valid Knowledge Graph containing
# deliberate errors.
#
# This allows us to prove that the SHACL validation layer
# catches invalid data.
#
# ============================================================


from pathlib import Path

from rdflib import (
    Graph,
    Namespace,
    Literal,
)

from rdflib.namespace import (
    RDF,
    XSD,
)


# ============================================================
# PATHS
# ============================================================

PROJECT_ROOT = Path(__file__).resolve().parent.parent


SOURCE_FILE = (
    PROJECT_ROOT
    / "data"
    / "rdf"
    / "cybersecurity_knowledge_graph.ttl"
)


INVALID_FILE = (
    PROJECT_ROOT
    / "data"
    / "rdf"
    / "cybersecurity_knowledge_graph_invalid.ttl"
)


# ============================================================
# NAMESPACE
# ============================================================

EX = Namespace(
    "http://example.org/cybersecurity/"
)


# ============================================================
# LOAD EXISTING VALID GRAPH
# ============================================================

graph = Graph()


graph.parse(
    SOURCE_FILE,
    format="turtle",
)


# ============================================================
# INVALID RECORD 1
# BAD CVSS SCORE
# ============================================================

invalid_vulnerability = EX.CVE_INVALID_001


graph.add(
    (
        invalid_vulnerability,
        RDF.type,
        EX.Vulnerability,
    )
)


graph.add(
    (
        invalid_vulnerability,
        EX.cveId,
        Literal(
            "CVE-2026-9999"
        ),
    )
)


graph.add(
    (
        invalid_vulnerability,
        EX.severity,
        Literal(
            "Critical"
        ),
    )
)


# Invalid because CVSS cannot exceed 10.
graph.add(
    (
        invalid_vulnerability,
        EX.cvssScore,
        Literal(
            15.5,
            datatype=XSD.decimal,
        ),
    )
)


graph.add(
    (
        invalid_vulnerability,
        EX.vulnerabilityType,
        Literal(
            "Remote Code Execution"
        ),
    )
)


# ============================================================
# INVALID RECORD 2
# INVALID SEVERITY
# ============================================================

invalid_vulnerability_2 = EX.CVE_INVALID_002


graph.add(
    (
        invalid_vulnerability_2,
        RDF.type,
        EX.Vulnerability,
    )
)


graph.add(
    (
        invalid_vulnerability_2,
        EX.cveId,
        Literal(
            "CVE-2026-9998"
        ),
    )
)


graph.add(
    (
        invalid_vulnerability_2,
        EX.severity,
        Literal(
            "Extreme"
        ),
    )
)


graph.add(
    (
        invalid_vulnerability_2,
        EX.cvssScore,
        Literal(
            9.5,
            datatype=XSD.decimal,
        ),
    )
)


graph.add(
    (
        invalid_vulnerability_2,
        EX.vulnerabilityType,
        Literal(
            "Authentication Bypass"
        ),
    )
)


# ============================================================
# INVALID RECORD 3
# THREAT ACTOR WITHOUT MALWARE
# ============================================================

invalid_actor = EX.TA999


graph.add(
    (
        invalid_actor,
        RDF.type,
        EX.ThreatActor,
    )
)


graph.add(
    (
        invalid_actor,
        EX.actorId,
        Literal(
            "TA999"
        ),
    )
)


graph.add(
    (
        invalid_actor,
        EX.actorName,
        Literal(
            "Unknown Phantom"
        ),
    )
)


graph.add(
    (
        invalid_actor,
        EX.actorType,
        Literal(
            "Unknown"
        ),
    )
)


graph.add(
    (
        invalid_actor,
        EX.primaryMotivation,
        Literal(
            "Unknown"
        ),
    )
)


# Notice:
#
# We intentionally DO NOT add:
#
# ex:TA999 ex:usesMalware ...
#
# This should cause SHACL validation to fail.


# ============================================================
# SAVE INVALID GRAPH
# ============================================================

graph.serialize(
    destination=str(
        INVALID_FILE
    ),
    format="turtle",
)


print(
    "Invalid test graph created:"
)

print(
    INVALID_FILE
)