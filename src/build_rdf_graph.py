# ============================================================
# STAGE 5
# BUILD CYBERSECURITY RDF KNOWLEDGE GRAPH
# ============================================================
#
# PURPOSE
# -------
# This script:
#
# 1. Loads all CSV datasets
# 2. Creates RDF resources for every entity
# 3. Adds datatype properties
# 4. Adds object-property relationships
# 5. Loads the ontology
# 6. Combines ontology + instance data
# 7. Saves the final Knowledge Graph as Turtle
#
# ============================================================


from pathlib import Path
import pandas as pd

from rdflib import (
    Graph,
    Namespace,
    URIRef,
    Literal,
)

from rdflib.namespace import (
    RDF,
    XSD,
)


# ============================================================
# 1. PROJECT PATHS
# ============================================================

PROJECT_ROOT = Path(__file__).resolve().parent.parent

RAW_DATA_DIR = PROJECT_ROOT / "data" / "raw"

ONTOLOGY_FILE = (
    PROJECT_ROOT
    / "ontology"
    / "cybersecurity_ontology.ttl"
)

RDF_OUTPUT_DIR = (
    PROJECT_ROOT
    / "data"
    / "rdf"
)

RDF_OUTPUT_DIR.mkdir(
    parents=True,
    exist_ok=True,
)

OUTPUT_FILE = (
    RDF_OUTPUT_DIR
    / "cybersecurity_knowledge_graph.ttl"
)


# ============================================================
# 2. RDF NAMESPACE
# ============================================================

# This must match the namespace used in our ontology.
EX = Namespace(
    "http://example.org/cybersecurity/"
)


# ============================================================
# 3. CREATE RDF GRAPH
# ============================================================

graph = Graph()


# Bind prefix so generated Turtle is readable.
#
# Instead of:
#
# <http://example.org/cybersecurity/ThreatActor>
#
# we will see:
#
# ex:ThreatActor
#
graph.bind(
    "ex",
    EX,
)


# ============================================================
# 4. LOAD EXISTING ONTOLOGY
# ============================================================

print("=" * 70)
print("BUILDING CYBERSECURITY RDF KNOWLEDGE GRAPH")
print("=" * 70)

print(
    f"\nLoading ontology:\n{ONTOLOGY_FILE}"
)


graph.parse(
    ONTOLOGY_FILE,
    format="turtle",
)


ontology_triple_count = len(graph)


print(
    f"\nOntology triples loaded: "
    f"{ontology_triple_count}"
)


# ============================================================
# 5. HELPER FUNCTION
# ============================================================

def entity_uri(entity_id): # type: ignore
    """
    Convert an entity ID into an RDF URI.

    Example:

    TA001

    becomes:

    http://example.org/cybersecurity/TA001
    """

    entity_id = str(entity_id).strip() # type: ignore

    return URIRef(
        f"{str(EX)}{entity_id}"
    )


# ============================================================
# 6. LOAD CSV FILES
# ============================================================

threat_actors = pd.read_csv(
    RAW_DATA_DIR / "threat_actors.csv"
)

malware = pd.read_csv(
    RAW_DATA_DIR / "malware.csv"
)

vulnerabilities = pd.read_csv(
    RAW_DATA_DIR / "vulnerabilities.csv"
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

ip_addresses = pd.read_csv(
    RAW_DATA_DIR / "ip_addresses.csv"
)

relationships = pd.read_csv(
    RAW_DATA_DIR / "relationships.csv"
)


# ============================================================
# 7. CREATE THREAT ACTOR ENTITIES
# ============================================================

for _, row in threat_actors.iterrows():

    subject = entity_uri(
        row["actor_id"]
    )

    # rdf:type tells the graph what class this entity belongs to.
    graph.add(
        (
            subject,
            RDF.type,
            EX.ThreatActor,
        )
    )

    graph.add(
        (
            subject,
            EX.actorId,
            Literal(
                row["actor_id"]
            ),
        )
    )

    graph.add(
        (
            subject,
            EX.actorName,
            Literal(
                row["actor_name"]
            ),
        )
    )

    graph.add(
        (
            subject,
            EX.actorType,
            Literal(
                row["actor_type"]
            ),
        )
    )

    graph.add(
        (
            subject,
            EX.primaryMotivation,
            Literal(
                row["primary_motivation"]
            ),
        )
    )


# ============================================================
# 8. CREATE MALWARE ENTITIES
# ============================================================

for _, row in malware.iterrows():

    subject = entity_uri(
        row["malware_id"]
    )

    graph.add(
        (
            subject,
            RDF.type,
            EX.Malware,
        )
    )

    graph.add(
        (
            subject,
            EX.malwareId,
            Literal(
                row["malware_id"]
            ),
        )
    )

    graph.add(
        (
            subject,
            EX.malwareName,
            Literal(
                row["malware_name"]
            ),
        )
    )

    graph.add(
        (
            subject,
            EX.malwareType,
            Literal(
                row["malware_type"]
            ),
        )
    )


# ============================================================
# 9. CREATE VULNERABILITY ENTITIES
# ============================================================

for _, row in vulnerabilities.iterrows():

    subject = entity_uri(
        row["cve_id"]
    )

    graph.add(
        (
            subject,
            RDF.type,
            EX.Vulnerability,
        )
    )

    graph.add(
        (
            subject,
            EX.cveId,
            Literal(
                row["cve_id"]
            ),
        )
    )

    graph.add(
        (
            subject,
            EX.severity,
            Literal(
                row["severity"]
            ),
        )
    )

    graph.add(
        (
            subject,
            EX.cvssScore,
            Literal(
                float(
                    row["cvss_score"]
                ),
                datatype=XSD.decimal,
            ),
        )
    )

    graph.add(
        (
            subject,
            EX.vulnerabilityType,
            Literal(
                row["vulnerability_type"]
            ),
        )
    )


# ============================================================
# 10. CREATE CAMPAIGN ENTITIES
# ============================================================

for _, row in campaigns.iterrows():

    subject = entity_uri(
        row["campaign_id"]
    )

    graph.add(
        (
            subject,
            RDF.type,
            EX.Campaign,
        )
    )

    graph.add(
        (
            subject,
            EX.campaignId,
            Literal(
                row["campaign_id"]
            ),
        )
    )

    graph.add(
        (
            subject,
            EX.campaignName,
            Literal(
                row["campaign_name"]
            ),
        )
    )

    graph.add(
        (
            subject,
            EX.attackVector,
            Literal(
                row["attack_vector"]
            ),
        )
    )


# ============================================================
# 11. CREATE ORGANIZATION ENTITIES
# ============================================================

for _, row in organizations.iterrows():

    subject = entity_uri(
        row["organization_id"]
    )

    graph.add(
        (
            subject,
            RDF.type,
            EX.Organization,
        )
    )

    graph.add(
        (
            subject,
            EX.organizationId,
            Literal(
                row["organization_id"]
            ),
        )
    )

    graph.add(
        (
            subject,
            EX.organizationName,
            Literal(
                row["organization_name"]
            ),
        )
    )

    graph.add(
        (
            subject,
            EX.industry,
            Literal(
                row["industry"]
            ),
        )
    )


# ============================================================
# 12. CREATE DOMAIN ENTITIES
# ============================================================

for _, row in domains.iterrows():

    subject = entity_uri(
        row["domain_id"]
    )

    graph.add(
        (
            subject,
            RDF.type,
            EX.Domain,
        )
    )

    graph.add(
        (
            subject,
            EX.domainId,
            Literal(
                row["domain_id"]
            ),
        )
    )

    graph.add(
        (
            subject,
            EX.domainName,
            Literal(
                row["domain_name"]
            ),
        )
    )


# ============================================================
# 13. CREATE IP ADDRESS ENTITIES
# ============================================================

for _, row in ip_addresses.iterrows():

    subject = entity_uri(
        row["ip_id"]
    )

    graph.add(
        (
            subject,
            RDF.type,
            EX.IPAddress,
        )
    )

    graph.add(
        (
            subject,
            EX.ipId,
            Literal(
                row["ip_id"]
            ),
        )
    )

    graph.add(
        (
            subject,
            EX.ipAddress,
            Literal(
                row["ip_address"]
            ),
        )
    )


# ============================================================
# 14. MAP CSV RELATIONSHIP NAMES TO RDF PROPERTIES
# ============================================================

RELATIONSHIP_MAP = {

    "USES_MALWARE":
        EX.usesMalware,

    "EXPLOITS":
        EX.exploits,

    "ATTRIBUTED_TO_CAMPAIGN":
        EX.attributedToCampaign,

    "TARGETS":
        EX.targets,

    "COMMUNICATES_WITH":
        EX.communicatesWith,

    "RESOLVES_TO":
        EX.resolvesTo,
}


# ============================================================
# 15. CREATE OBJECT-PROPERTY RELATIONSHIPS
# ============================================================

relationship_triples_added = 0


for _, row in relationships.iterrows():

    source = entity_uri(
        row["source_id"]
    )

    target = entity_uri(
        row["target_id"]
    )

    relationship_name = (
        row["relationship"]
    )


    predicate = RELATIONSHIP_MAP.get(
        relationship_name
    )


    if predicate is None:

        print(
            f"WARNING: Unknown relationship "
            f"type: {relationship_name}"
        )

        continue


    graph.add(
        (
            source,
            predicate,
            target,
        )
    )


    relationship_triples_added += 1


# ============================================================
# 16. KNOWLEDGE GRAPH STATISTICS
# ============================================================

total_triples = len(graph)

instance_triples = (
    total_triples
    - ontology_triple_count
)


print("\n" + "-" * 70)

print(
    f"Threat Actors: "
    f"{len(threat_actors)}"
)

print(
    f"Malware: "
    f"{len(malware)}"
)

print(
    f"Vulnerabilities: "
    f"{len(vulnerabilities)}"
)

print(
    f"Campaigns: "
    f"{len(campaigns)}"
)

print(
    f"Organizations: "
    f"{len(organizations)}"
)

print(
    f"Domains: "
    f"{len(domains)}"
)

print(
    f"IP Addresses: "
    f"{len(ip_addresses)}"
)

print(
    f"Relationship triples added: "
    f"{relationship_triples_added}"
)

print(
    f"Instance/data triples: "
    f"{instance_triples}"
)

print(
    f"Total triples including ontology: "
    f"{total_triples}"
)


# ============================================================
# 17. SERIALIZE RDF GRAPH
# ============================================================

graph.serialize(
    destination=str(
        OUTPUT_FILE
    ),
    format="turtle",
)


# ============================================================
# 18. FINAL RESULT
# ============================================================

print("\n" + "=" * 70)

print(
    "RDF KNOWLEDGE GRAPH CREATED SUCCESSFULLY"
)

print("=" * 70)

print(
    f"\nOutput file:\n{OUTPUT_FILE}"
)