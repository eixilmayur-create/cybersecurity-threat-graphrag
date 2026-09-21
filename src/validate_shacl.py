# ============================================================
# STAGE 7
# SHACL VALIDATION SCRIPT
# ============================================================
#
# PURPOSE
# -------
# Validate our Cybersecurity RDF Knowledge Graph against
# the SHACL rules defined in cybersecurity_shapes.ttl.
#
# We will:
#
# 1. Load the RDF data graph
# 2. Load the SHACL shapes graph
# 3. Run pySHACL validation
# 4. Print conformity result
# 5. Save validation reports
#
# ============================================================


from pathlib import Path

from rdflib import Graph

from pyshacl import validate # type: ignore


# ============================================================
# 1. PROJECT PATHS
# ============================================================

PROJECT_ROOT = Path(__file__).resolve().parent.parent


DATA_GRAPH_FILE = (
    PROJECT_ROOT
    / "data"
    / "rdf"
    / "cybersecurity_knowledge_graph.ttl"
)


SHAPES_FILE = (
    PROJECT_ROOT
    / "shapes"
    / "cybersecurity_shapes.ttl"
)


OUTPUT_DIR = (
    PROJECT_ROOT
    / "outputs"
    / "validation"
)


OUTPUT_DIR.mkdir(
    parents=True,
    exist_ok=True,
)


REPORT_TTL_FILE = (
    OUTPUT_DIR
    / "shacl_validation_report.ttl"
)


REPORT_TEXT_FILE = (
    OUTPUT_DIR
    / "shacl_validation_report.txt"
)


# ============================================================
# 2. LOAD DATA GRAPH
# ============================================================

print("=" * 70)
print("CYBERSECURITY SHACL VALIDATION")
print("=" * 70)


data_graph = Graph()


data_graph.parse(
    DATA_GRAPH_FILE,
    format="turtle",
)


print(
    f"\nData graph triples: "
    f"{len(data_graph)}"
)


# ============================================================
# 3. LOAD SHACL SHAPES
# ============================================================

shapes_graph = Graph()


shapes_graph.parse(
    SHAPES_FILE,
    format="turtle",
)


print(
    f"SHACL triples: "
    f"{len(shapes_graph)}"
)


# ============================================================
# 4. RUN SHACL VALIDATION
# ============================================================

conforms, report_graph, report_text = validate( # type: ignore

    # RDF Knowledge Graph we want to validate.
    data_graph=data_graph,

    # SHACL validation rules.
    shacl_graph=shapes_graph,

    # We are not enabling extra OWL reasoning here.
    inference="none",

    # Stop only after collecting all validation results.
    abort_on_first=False,

    # We want warnings/information to remain visible.
    allow_infos=False,

    allow_warnings=False,

    # Generate detailed validation result information.
    meta_shacl=False,

    advanced=True,
)


# ============================================================
# 5. DISPLAY RESULT
# ============================================================

print("\n")
print("=" * 70)
print("VALIDATION RESULT")
print("=" * 70)


print(
    f"\nConforms: {conforms}"
)


if conforms:

    print(
        "\nRESULT: Knowledge Graph passed SHACL validation."
    )

else:

    print(
        "\nRESULT: Knowledge Graph contains SHACL violations."
    )


# ============================================================
# 6. DISPLAY FULL REPORT
# ============================================================

print("\n")
print("-" * 70)
print("SHACL REPORT")
print("-" * 70)

print(report_text) # type: ignore


# ============================================================
# 7. SAVE RDF VALIDATION REPORT
# ============================================================

report_graph.serialize( # type: ignore
    destination=str(
        REPORT_TTL_FILE
    ),
    format="turtle",
)


# ============================================================
# 8. SAVE HUMAN-READABLE REPORT
# ============================================================

with open(
    REPORT_TEXT_FILE,
    "w",
    encoding="utf-8",
) as file:

    file.write(
        report_text # type: ignore
    )


# ============================================================
# 9. FINAL OUTPUT
# ============================================================

print("\n")
print("=" * 70)
print("VALIDATION COMPLETED")
print("=" * 70)


print(
    f"\nRDF validation report:\n"
    f"{REPORT_TTL_FILE}"
)


print(
    f"\nText validation report:\n"
    f"{REPORT_TEXT_FILE}"
)