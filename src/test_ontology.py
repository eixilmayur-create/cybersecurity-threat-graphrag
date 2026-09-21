# ============================================================
# STAGE 4
# ONTOLOGY PARSING TEST
# ============================================================
#
# PURPOSE
# -------
# Load our Turtle ontology with RDFLib and verify that
# the RDF/OWL syntax is valid.
#
# ============================================================


from pathlib import Path
from rdflib import Graph, RDF, OWL


# ============================================================
# PROJECT PATH
# ============================================================

PROJECT_ROOT = Path(__file__).resolve().parent.parent

ONTOLOGY_FILE = (
    PROJECT_ROOT
    / "ontology"
    / "cybersecurity_ontology.ttl"
)


# ============================================================
# LOAD ONTOLOGY
# ============================================================

graph = Graph()


print("=" * 60)
print("CYBERSECURITY ONTOLOGY TEST")
print("=" * 60)


print(
    f"\nLoading ontology:\n{ONTOLOGY_FILE}"
)


graph.parse(
    ONTOLOGY_FILE,
    format="turtle",
)


# ============================================================
# BASIC GRAPH STATISTICS
# ============================================================

print(
    f"\nTotal RDF triples: {len(graph)}"
)


# ============================================================
# COUNT OWL CLASSES
# ============================================================

classes = set(
    graph.subjects(
        RDF.type,
        OWL.Class,
    )
)


print(
    f"OWL Classes: {len(classes)}"
)


# ============================================================
# COUNT OBJECT PROPERTIES
# ============================================================

object_properties = set(
    graph.subjects(
        RDF.type,
        OWL.ObjectProperty,
    )
)


print(
    f"Object Properties: {len(object_properties)}"
)


# ============================================================
# COUNT DATATYPE PROPERTIES
# ============================================================

datatype_properties = set(
    graph.subjects(
        RDF.type,
        OWL.DatatypeProperty,
    )
)


print(
    f"Datatype Properties: {len(datatype_properties)}"
)


# ============================================================
# DISPLAY CLASSES
# ============================================================

print("\nOntology Classes:")

for ontology_class in sorted(
    classes,
    key=str,
):

    print(
        f"  - {ontology_class}"
    )


# ============================================================
# DISPLAY OBJECT PROPERTIES
# ============================================================

print("\nObject Properties:")

for prop in sorted(
    object_properties,
    key=str,
):

    print(
        f"  - {prop}"
    )


# ============================================================
# RESULT
# ============================================================

print("\n" + "=" * 60)
print("ONTOLOGY PARSED SUCCESSFULLY")
print("=" * 60)