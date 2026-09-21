# ============================================================
# STAGE 8
# CYBERSECURITY SEMANTIC VALIDATION FRAMEWORK
# ============================================================
#
# PURPOSE
# -------
# This script performs semantic quality checks that go beyond
# simple field-level SHACL validation.
#
# We will check:
#
# 1. Orphan Threat Actors
# 2. Orphan Malware
# 3. Unused Vulnerabilities
# 4. Campaigns with no targets
# 5. Domains with no IP mappings
# 6. IP addresses with no incoming domain relation
# 7. Inconsistent Severity vs CVSS
# 8. Broken multi-hop threat investigation paths
# 9. Unused Organizations
# 10. Graph quality score
#
# ============================================================


from pathlib import Path
import pandas as pd

from rdflib import (
    Graph,
    Namespace,
)

from rdflib.namespace import RDF


# ============================================================
# 1. PROJECT PATHS
# ============================================================

PROJECT_ROOT = Path(__file__).resolve().parent.parent


GRAPH_FILE = (
    PROJECT_ROOT
    / "data"
    / "rdf"
    / "cybersecurity_knowledge_graph.ttl"
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


DETAIL_REPORT_FILE = (
    OUTPUT_DIR
    / "semantic_validation_details.csv"
)


SUMMARY_REPORT_FILE = (
    OUTPUT_DIR
    / "semantic_validation_summary.csv"
)


# ============================================================
# 2. RDF NAMESPACE
# ============================================================

EX = Namespace(
    "http://example.org/cybersecurity/"
)


# ============================================================
# 3. LOAD KNOWLEDGE GRAPH
# ============================================================

graph = Graph()


print("=" * 75)
print("CYBERSECURITY SEMANTIC VALIDATION FRAMEWORK")
print("=" * 75)


graph.parse(
    GRAPH_FILE,
    format="turtle",
)


print(
    f"\nKnowledge Graph triples loaded: {len(graph)}"
)


# ============================================================
# 4. VALIDATION RESULT STORAGE
# ============================================================

validation_results: list[dict[str, str]] = []


def add_result(
    rule_id: str,
    rule_name: str,
    severity: str,
    entity: object,
    status: str,
    message: str,
) -> None:
    """
    Store one validation result.

    status:
        PASS
        FAIL
    """

    validation_results.append(
        {
            "rule_id": rule_id,
            "rule_name": rule_name,
            "severity": severity,
            "entity": str(entity),
            "status": status,
            "message": message,
        }
    )


# ============================================================
# RULE 1
# THREAT ACTOR MUST USE MALWARE
# ============================================================

threat_actors = set(
    graph.subjects(
        RDF.type,
        EX.ThreatActor,
    )
)


for actor in threat_actors:

    malware_links = list(
        graph.objects(
            actor,
            EX.usesMalware,
        )
    )

    if malware_links:

        add_result(
            "SEM001",
            "Threat Actor has malware relationship",
            "High",
            actor,
            "PASS",
            "Threat Actor is connected to at least one Malware entity.",
        )

    else:

        add_result(
            "SEM001",
            "Threat Actor has malware relationship",
            "High",
            actor,
            "FAIL",
            "Threat Actor has no usesMalware relationship.",
        )


# ============================================================
# RULE 2
# MALWARE MUST BE USED BY A THREAT ACTOR
# ============================================================

malware_entities = set(
    graph.subjects(
        RDF.type,
        EX.Malware,
    )
)


for malware in malware_entities:

    actors_using_malware = list(
        graph.subjects(
            EX.usesMalware,
            malware,
        )
    )

    if actors_using_malware:

        add_result(
            "SEM002",
            "Malware linked to Threat Actor",
            "Medium",
            malware,
            "PASS",
            "Malware is linked to at least one Threat Actor.",
        )

    else:

        add_result(
            "SEM002",
            "Malware linked to Threat Actor",
            "Medium",
            malware,
            "FAIL",
            "Malware exists but is not linked to any Threat Actor.",
        )


# ============================================================
# RULE 3
# MALWARE MUST EXPLOIT A VULNERABILITY
# ============================================================

for malware in malware_entities:

    vulnerabilities = list(
        graph.objects(
            malware,
            EX.exploits,
        )
    )

    if vulnerabilities:

        add_result(
            "SEM003",
            "Malware exploits vulnerability",
            "High",
            malware,
            "PASS",
            "Malware is linked to at least one Vulnerability.",
        )

    else:

        add_result(
            "SEM003",
            "Malware exploits vulnerability",
            "High",
            malware,
            "FAIL",
            "Malware has no vulnerability relationship.",
        )


# ============================================================
# RULE 4
# VULNERABILITY SHOULD BE REFERENCED BY MALWARE
# ============================================================

vulnerability_entities = set(
    graph.subjects(
        RDF.type,
        EX.Vulnerability,
    )
)


for vulnerability in vulnerability_entities:

    incoming_links = list(
        graph.subjects(
            EX.exploits,
            vulnerability,
        )
    )

    if incoming_links:

        add_result(
            "SEM004",
            "Vulnerability referenced by malware",
            "Medium",
            vulnerability,
            "PASS",
            "Vulnerability is referenced by malware.",
        )

    else:

        add_result(
            "SEM004",
            "Vulnerability referenced by malware",
            "Medium",
            vulnerability,
            "FAIL",
            "Vulnerability exists but is not connected to malware.",
        )


# ============================================================
# RULE 5
# CAMPAIGN MUST TARGET AN ORGANIZATION
# ============================================================

campaigns = set(
    graph.subjects(
        RDF.type,
        EX.Campaign,
    )
)


for campaign in campaigns:

    targets = list(
        graph.objects(
            campaign,
            EX.targets,
        )
    )

    if targets:

        add_result(
            "SEM005",
            "Campaign targets organization",
            "High",
            campaign,
            "PASS",
            "Campaign targets at least one Organization.",
        )

    else:

        add_result(
            "SEM005",
            "Campaign targets organization",
            "High",
            campaign,
            "FAIL",
            "Campaign does not target any Organization.",
        )


# ============================================================
# RULE 6
# ORGANIZATION SHOULD BE TARGETED BY A CAMPAIGN
# ============================================================

organizations = set(
    graph.subjects(
        RDF.type,
        EX.Organization,
    )
)


for organization in organizations:

    campaigns_targeting_org = list(
        graph.subjects(
            EX.targets,
            organization,
        )
    )

    if campaigns_targeting_org:

        add_result(
            "SEM006",
            "Organization connected to campaign",
            "Low",
            organization,
            "PASS",
            "Organization is connected to at least one Campaign.",
        )

    else:

        add_result(
            "SEM006",
            "Organization connected to campaign",
            "Low",
            organization,
            "FAIL",
            "Organization exists but is not targeted by any Campaign.",
        )


# ============================================================
# RULE 7
# DOMAIN MUST RESOLVE TO IP ADDRESS
# ============================================================

domains = set(
    graph.subjects(
        RDF.type,
        EX.Domain,
    )
)


for domain in domains:

    ip_links = list(
        graph.objects(
            domain,
            EX.resolvesTo,
        )
    )

    if ip_links:

        add_result(
            "SEM007",
            "Domain resolves to IP",
            "High",
            domain,
            "PASS",
            "Domain resolves to at least one IP Address.",
        )

    else:

        add_result(
            "SEM007",
            "Domain resolves to IP",
            "High",
            domain,
            "FAIL",
            "Domain has no IP resolution relationship.",
        )


# ============================================================
# RULE 8
# IP ADDRESS SHOULD HAVE AN INCOMING DOMAIN RELATIONSHIP
# ============================================================

ip_entities = set(
    graph.subjects(
        RDF.type,
        EX.IPAddress,
    )
)


for ip_entity in ip_entities:

    domains_pointing_to_ip = list(
        graph.subjects(
            EX.resolvesTo,
            ip_entity,
        )
    )

    if domains_pointing_to_ip:

        add_result(
            "SEM008",
            "IP linked from domain",
            "Low",
            ip_entity,
            "PASS",
            "IP Address is referenced by a Domain.",
        )

    else:

        add_result(
            "SEM008",
            "IP linked from domain",
            "Low",
            ip_entity,
            "FAIL",
            "IP Address exists but is not referenced by any Domain.",
        )


# ============================================================
# RULE 9
# CHECK SEVERITY AGAINST CVSS
# ============================================================
#
# Simplified learning thresholds:
#
# 0.0 - 3.9   -> Low
# 4.0 - 6.9   -> Medium
# 7.0 - 8.9   -> High
# 9.0 - 10.0  -> Critical
#
# ============================================================


def expected_severity(cvss_score: float) -> str:
    """
    Return expected severity based on CVSS score.
    """

    if cvss_score >= 9.0:
        return "Critical"

    if cvss_score >= 7.0:
        return "High"

    if cvss_score >= 4.0:
        return "Medium"

    return "Low"


for vulnerability in vulnerability_entities:

    severity_values = list(
        graph.objects(
            vulnerability,
            EX.severity,
        )
    )

    cvss_values = list(
        graph.objects(
            vulnerability,
            EX.cvssScore,
        )
    )


    if not severity_values or not cvss_values:

        continue


    severity = str(
        severity_values[0]
    )


    cvss_score = float(
        cvss_values[0] # type: ignore
    )


    expected = expected_severity(
        cvss_score
    )


    if severity == expected:

        add_result(
            "SEM009",
            "Severity consistent with CVSS",
            "High",
            vulnerability,
            "PASS",
            (
                f"Severity {severity} is consistent "
                f"with CVSS {cvss_score}."
            ),
        )

    else:

        add_result(
            "SEM009",
            "Severity consistent with CVSS",
            "High",
            vulnerability,
            "FAIL",
            (
                f"Severity is {severity}, but CVSS "
                f"{cvss_score} maps to {expected}."
            ),
        )


# ============================================================
# RULE 10
# FULL THREAT INVESTIGATION PATH
# ============================================================
#
# ThreatActor
#      |
#      +--> Malware
#      |      |
#      |      +--> Vulnerability
#      |
#      +--> Campaign
#             |
#             +--> Organization
#
# We verify that each actor participates in a complete
# investigation path.
#
# ============================================================

for actor in threat_actors:

    complete_path_found = False


    malware_links = list(
        graph.objects(
            actor,
            EX.usesMalware,
        )
    )


    campaign_links = list(
        graph.objects(
            actor,
            EX.attributedToCampaign,
        )
    )


    for malware in malware_links:

        vulnerability_links = list(
            graph.objects(
                malware,
                EX.exploits,
            )
        )


        for campaign in campaign_links:

            organization_links = list(
                graph.objects(
                    campaign,
                    EX.targets,
                )
            )


            if (
                vulnerability_links
                and organization_links
            ):

                complete_path_found = True
                break


        if complete_path_found:
            break


    if complete_path_found:

        add_result(
            "SEM010",
            "Complete threat investigation path",
            "Critical",
            actor,
            "PASS",
            (
                "Threat Actor participates in a complete "
                "Actor -> Malware -> Vulnerability and "
                "Actor -> Campaign -> Organization path."
            ),
        )

    else:

        add_result(
            "SEM010",
            "Complete threat investigation path",
            "Critical",
            actor,
            "FAIL",
            (
                "Threat Actor does not participate in a "
                "complete threat investigation path."
            ),
        )


# ============================================================
# RULE 11
# MALWARE SHOULD HAVE INFRASTRUCTURE
# ============================================================

for malware in malware_entities:

    domains_used = list(
        graph.objects(
            malware,
            EX.communicatesWith,
        )
    )

    valid_infrastructure_path = False


    for domain in domains_used:

        ips = list(
            graph.objects(
                domain,
                EX.resolvesTo,
            )
        )

        if ips:

            valid_infrastructure_path = True
            break


    if valid_infrastructure_path:

        add_result(
            "SEM011",
            "Malware infrastructure path",
            "High",
            malware,
            "PASS",
            (
                "Malware has a complete "
                "Malware -> Domain -> IP path."
            ),
        )

    else:

        add_result(
            "SEM011",
            "Malware infrastructure path",
            "High",
            malware,
            "FAIL",
            (
                "Malware is missing a complete "
                "Domain -> IP infrastructure path."
            ),
        )


# ============================================================
# 5. CONVERT RESULTS TO DATAFRAME
# ============================================================

results_df = pd.DataFrame(
    validation_results
)


# ============================================================
# 6. CALCULATE QUALITY SCORE
# ============================================================
#
# Severity weights:
#
# Critical = 4
# High     = 3
# Medium   = 2
# Low      = 1
#
# PASS receives the full weight.
# FAIL receives zero.
#
# Score:
#
# achieved_weight / possible_weight * 100
#
# ============================================================

SEVERITY_WEIGHTS = {
    "Critical": 4,
    "High": 3,
    "Medium": 2,
    "Low": 1,
}


possible_score = 0
achieved_score = 0


for _, row in results_df.iterrows():

    weight = SEVERITY_WEIGHTS[
        row["severity"]
    ]

    possible_score += weight


    if row["status"] == "PASS":

        achieved_score += weight


quality_score = (
    achieved_score
    / possible_score
    * 100
    if possible_score > 0
    else 0
)


# ============================================================
# 7. SUMMARY METRICS
# ============================================================

total_checks = len(
    results_df
)


passed_checks = len(
    results_df[
        results_df["status"] == "PASS"
    ]
)


failed_checks = len(
    results_df[
        results_df["status"] == "FAIL"
    ]
)


summary_df = pd.DataFrame(
    [
        {
            "total_checks": total_checks,
            "passed_checks": passed_checks,
            "failed_checks": failed_checks,
            "quality_score_percent": round(
                quality_score,
                2,
            ),
        }
    ]
)


# ============================================================
# 8. DISPLAY FAILED RULES
# ============================================================

print("\n")
print("=" * 75)
print("SEMANTIC VALIDATION FAILURES")
print("=" * 75)


failures = results_df[
    results_df["status"] == "FAIL"
]


if failures.empty:

    print(
        "\nNo semantic validation failures found."
    )

else:

    for _, row in failures.iterrows():

        print(
            f"\nRule: {row['rule_id']}"
        )

        print(
            f"Name: {row['rule_name']}"
        )

        print(
            f"Severity: {row['severity']}"
        )

        print(
            f"Entity: {row['entity']}"
        )

        print(
            f"Message: {row['message']}"
        )


# ============================================================
# 9. SAVE REPORTS
# ============================================================

results_df.to_csv(
    DETAIL_REPORT_FILE,
    index=False,
)


summary_df.to_csv(
    SUMMARY_REPORT_FILE,
    index=False,
)


# ============================================================
# 10. FINAL SUMMARY
# ============================================================

print("\n")
print("=" * 75)
print("SEMANTIC QUALITY SUMMARY")
print("=" * 75)


print(
    f"\nTotal checks: {total_checks}"
)

print(
    f"Passed checks: {passed_checks}"
)

print(
    f"Failed checks: {failed_checks}"
)

print(
    f"Graph Quality Score: "
    f"{quality_score:.2f}%"
)


print(
    f"\nDetailed report:\n"
    f"{DETAIL_REPORT_FILE}"
)


print(
    f"\nSummary report:\n"
    f"{SUMMARY_REPORT_FILE}"
)


print("\n")
print("=" * 75)
print("SEMANTIC VALIDATION COMPLETED")
print("=" * 75)