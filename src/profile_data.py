# ============================================================
# STAGE 3
# CYBERSECURITY DATA PROFILING
# ============================================================
#
# PURPOSE
# -------
# Before building an RDF Knowledge Graph, we first inspect
# the raw data.
#
# We will check:
#
# 1. Row count
# 2. Column count
# 3. Missing values
# 4. Duplicate rows
# 5. Duplicate IDs
# 6. Relationship types
# 7. Broken relationship references
#
# This is important because bad source data creates
# bad Knowledge Graphs.
#
# ============================================================


from pathlib import Path
import pandas as pd


# ============================================================
# 1. DEFINE PROJECT PATHS
# ============================================================

# Current file:
# cybersecurity-threat-graphrag/src/profile_data.py
#
# parent.parent moves back to:
# cybersecurity-threat-graphrag/
PROJECT_ROOT = Path(__file__).resolve().parent.parent

RAW_DATA_DIR = PROJECT_ROOT / "data" / "raw"

OUTPUT_DIR = PROJECT_ROOT / "outputs"

OUTPUT_DIR.mkdir(
    parents=True,
    exist_ok=True,
)


# ============================================================
# 2. DEFINE DATASETS
# ============================================================

DATA_FILES = [
    "threat_actors.csv",
    "malware.csv",
    "vulnerabilities.csv",
    "campaigns.csv",
    "organizations.csv",
    "domains.csv",
    "ip_addresses.csv",
    "relationships.csv",
]


# ============================================================
# 3. PROFILE EACH DATASET
# ============================================================

profile_results: list[dict[str, object]] = []


print("\n")
print("=" * 70)
print("CYBERSECURITY DATA PROFILING")
print("=" * 70)


for filename in DATA_FILES:

    file_path = RAW_DATA_DIR / filename

    print("\n")
    print("-" * 70)
    print(f"DATASET: {filename}")
    print("-" * 70)

    # Load CSV.
    df = pd.read_csv(file_path)

    # ----------------------------------------
    # BASIC DATA INFORMATION
    # ----------------------------------------

    row_count = len(df)

    column_count = len(df.columns)

    duplicate_rows = df.duplicated().sum()

    total_missing_values = df.isnull().sum().sum()


    print(f"Rows: {row_count}")
    print(f"Columns: {column_count}")
    print(f"Duplicate rows: {duplicate_rows}")
    print(f"Missing values: {total_missing_values}")


    # ----------------------------------------
    # DISPLAY COLUMN NAMES
    # ----------------------------------------

    print("\nColumns:")

    for column in df.columns:
        print(f"  - {column}")


    # ----------------------------------------
    # MISSING VALUE CHECK
    # ----------------------------------------

    print("\nMissing values by column:")

    missing_by_column = df.isnull().sum()

    for column, missing_count in missing_by_column.items():

        print(
            f"  {column:<30} "
            f"{missing_count}"
        )


    # ----------------------------------------
    # DUPLICATE ID CHECK
    # ----------------------------------------

    # Entity tables usually have one ID column.
    #
    # We automatically detect columns ending
    # with "_id".
    #
    # relationships.csv is excluded because
    # source_id and target_id naturally repeat.

    if filename != "relationships.csv":

        id_columns = [
            column
            for column in df.columns
            if column.endswith("_id")
            or column == "cve_id"
        ]

        if id_columns:

            id_column = id_columns[0]

            duplicate_ids = (
                df[id_column]
                .duplicated()
                .sum()
            )

            print(
                f"\nDuplicate IDs "
                f"({id_column}): "
                f"{duplicate_ids}"
            )

        else:

            duplicate_ids = 0

    else:

        duplicate_ids = 0


    # ----------------------------------------
    # SAVE PROFILE SUMMARY
    # ----------------------------------------

    profile_results.append(
        {
            "dataset": filename,
            "rows": row_count,
            "columns": column_count,
            "missing_values": total_missing_values,
            "duplicate_rows": duplicate_rows,
            "duplicate_ids": duplicate_ids,
        }
    )


# ============================================================
# 4. LOAD RELATIONSHIP TABLE
# ============================================================

relationships = pd.read_csv(
    RAW_DATA_DIR / "relationships.csv"
)


print("\n")
print("=" * 70)
print("RELATIONSHIP ANALYSIS")
print("=" * 70)


# ============================================================
# 5. COUNT RELATIONSHIP TYPES
# ============================================================

relationship_counts = (
    relationships["relationship"]
    .value_counts()
)


print("\nRelationship types:")

for relationship_type, count in relationship_counts.items():

    print(
        f"  {relationship_type:<30} "
        f"{count}"
    )


# ============================================================
# 6. BUILD MASTER ENTITY ID SET
# ============================================================

# We collect every valid entity ID from every entity file.
#
# This allows us to check whether relationships refer
# to entities that actually exist.


entity_files = {
    "threat_actors.csv": "actor_id",
    "malware.csv": "malware_id",
    "vulnerabilities.csv": "cve_id",
    "campaigns.csv": "campaign_id",
    "organizations.csv": "organization_id",
    "domains.csv": "domain_id",
    "ip_addresses.csv": "ip_id",
}


valid_entity_ids: set[str] = set()


for filename, id_column in entity_files.items():

    df = pd.read_csv(
        RAW_DATA_DIR / filename
    )

    valid_entity_ids.update(
        str(entity_id) for entity_id in df[id_column].tolist()
    )


print(
    f"\nTotal unique entity IDs: "
    f"{len(valid_entity_ids)}"
)


# ============================================================
# 7. CHECK BROKEN SOURCE REFERENCES
# ============================================================

invalid_source_rows = relationships[
    ~relationships["source_id"]
    .astype(str)
    .isin(valid_entity_ids)
]


# ============================================================
# 8. CHECK BROKEN TARGET REFERENCES
# ============================================================

invalid_target_rows = relationships[
    ~relationships["target_id"]
    .astype(str)
    .isin(valid_entity_ids)
]


print(
    "\nInvalid source references: "
    f"{len(invalid_source_rows)}"
)

print(
    "Invalid target references: "
    f"{len(invalid_target_rows)}"
)


# ============================================================
# 9. CHECK DUPLICATE RELATIONSHIPS
# ============================================================

duplicate_relationships = (
    relationships.duplicated().sum()
)


print(
    "Duplicate relationships: "
    f"{duplicate_relationships}"
)


# ============================================================
# 10. SAVE PROFILE REPORT
# ============================================================

profile_df = pd.DataFrame(
    profile_results
)


profile_output_file = (
    OUTPUT_DIR /
    "data_profile_summary.csv"
)


profile_df.to_csv(
    profile_output_file,
    index=False,
)


# ============================================================
# 11. SAVE RELATIONSHIP QUALITY REPORT
# ============================================================

relationship_quality = pd.DataFrame(
    [
        {
            "total_relationships":
                len(relationships),

            "relationship_types":
                relationships[
                    "relationship"
                ].nunique(),

            "invalid_source_references":
                len(invalid_source_rows),

            "invalid_target_references":
                len(invalid_target_rows),

            "duplicate_relationships":
                duplicate_relationships,
        }
    ]
)


relationship_output_file = (
    OUTPUT_DIR /
    "relationship_quality_summary.csv"
)


relationship_quality.to_csv(
    relationship_output_file,
    index=False,
)


# ============================================================
# 12. FINAL SUMMARY
# ============================================================

print("\n")
print("=" * 70)
print("PROFILE COMPLETE")
print("=" * 70)

print(
    "\nData profile saved to:"
)

print(
    profile_output_file
)

print(
    "\nRelationship quality report saved to:"
)

print(
    relationship_output_file
)


if (
    len(invalid_source_rows) == 0
    and len(invalid_target_rows) == 0
    and duplicate_relationships == 0
):

    print(
        "\nRESULT: Dataset passed basic integrity checks."
    )

else:

    print(
        "\nRESULT: Dataset contains quality issues."
    )