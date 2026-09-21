# ============================================================
# CYBERSECURITY THREAT INTELLIGENCE DATASET GENERATOR
# ============================================================
#
# PURPOSE
# -------
# Creates a small synthetic cybersecurity threat intelligence
# dataset for our Knowledge Graph and Graph-RAG project.
#
# The dataset contains:
#
#   Threat Actors
#   Malware
#   Vulnerabilities
#   Campaigns
#   Organizations
#   Domains
#   IP Addresses
#   Indicators
#
# Later these tables will become RDF entities and relationships.
#
# ============================================================


from pathlib import Path
import pandas as pd


# ============================================================
# 1. PROJECT PATHS
# ============================================================

# __file__ represents this Python file:
#
# cybersecurity-threat-graphrag/src/create_dataset.py
#
# parent.parent therefore points to:
#
# cybersecurity-threat-graphrag/
#
PROJECT_ROOT = Path(__file__).resolve().parent.parent

DATA_DIR = PROJECT_ROOT / "data" / "raw"

# Create the directory if it does not already exist.
DATA_DIR.mkdir(parents=True, exist_ok=True)


# ============================================================
# 2. THREAT ACTORS
# ============================================================

threat_actors = pd.DataFrame(
    [
        ["TA001", "APT-29", "State-Sponsored", "Credential Theft"],
        ["TA002", "Shadow Spider", "Cybercrime", "Ransomware"],
        ["TA003", "Crimson Fox", "Cybercrime", "Financial Theft"],
        ["TA004", "Silent Raven", "Espionage", "Data Exfiltration"],
        ["TA005", "Dark Hydra", "Cybercrime", "Credential Theft"],
    ],
    columns=[
        "actor_id",
        "actor_name",
        "actor_type",
        "primary_motivation",
    ],
)


# ============================================================
# 3. MALWARE
# ============================================================

malware = pd.DataFrame(
    [
        ["MAL001", "SolarDrop", "Backdoor"],
        ["MAL002", "BlackCrypt", "Ransomware"],
        ["MAL003", "CredentialFox", "Credential Stealer"],
        ["MAL004", "SilentLoader", "Loader"],
        ["MAL005", "HydraBot", "Botnet"],
    ],
    columns=[
        "malware_id",
        "malware_name",
        "malware_type",
    ],
)


# ============================================================
# 4. VULNERABILITIES
# ============================================================

vulnerabilities = pd.DataFrame(
    [
        ["CVE-2026-1001", "Critical", 9.8, "Remote Code Execution"],
        ["CVE-2026-1002", "High", 8.1, "Privilege Escalation"],
        ["CVE-2026-1003", "Critical", 9.5, "Authentication Bypass"],
        ["CVE-2026-1004", "Medium", 6.5, "Information Disclosure"],
        ["CVE-2026-1005", "High", 8.8, "Remote Code Execution"],
    ],
    columns=[
        "cve_id",
        "severity",
        "cvss_score",
        "vulnerability_type",
    ],
)


# ============================================================
# 5. CAMPAIGNS
# ============================================================

campaigns = pd.DataFrame(
    [
        ["CAM001", "Operation Nightfall", "Phishing"],
        ["CAM002", "Operation Black Ice", "Ransomware"],
        ["CAM003", "Operation Silent Web", "Credential Theft"],
        ["CAM004", "Operation Red Cloud", "Espionage"],
    ],
    columns=[
        "campaign_id",
        "campaign_name",
        "attack_vector",
    ],
)


# ============================================================
# 6. ORGANIZATIONS
# ============================================================

organizations = pd.DataFrame(
    [
        ["ORG001", "FinBank Ltd", "Banking"],
        ["ORG002", "HealthSecure", "Healthcare"],
        ["ORG003", "CloudRetail", "Retail"],
        ["ORG004", "TechNova", "Technology"],
        ["ORG005", "PaySphere", "FinTech"],
    ],
    columns=[
        "organization_id",
        "organization_name",
        "industry",
    ],
)


# ============================================================
# 7. DOMAINS
# ============================================================

domains = pd.DataFrame(
    [
        ["DOM001", "secure-update-example.com"],
        ["DOM002", "cloud-login-example.net"],
        ["DOM003", "payment-check-example.org"],
        ["DOM004", "mail-auth-example.net"],
        ["DOM005", "software-update-example.org"],
    ],
    columns=[
        "domain_id",
        "domain_name",
    ],
)


# ============================================================
# 8. IP ADDRESSES
# ============================================================

# Documentation-only IP address ranges are used so that
# we do not accidentally reference real malicious infrastructure.

ip_addresses = pd.DataFrame(
    [
        ["IP001", "192.0.2.10"],
        ["IP002", "192.0.2.20"],
        ["IP003", "198.51.100.30"],
        ["IP004", "198.51.100.40"],
        ["IP005", "203.0.113.50"],
    ],
    columns=[
        "ip_id",
        "ip_address",
    ],
)


# ============================================================
# 9. GRAPH RELATIONSHIPS
# ============================================================

# This table is the most important part of the project.
#
# It represents relationships:
#
# source_entity ----relationship----> target_entity
#
# Later each row becomes an RDF triple.

relationships = pd.DataFrame(
    [

        # ----------------------------------------------------
        # Threat Actor -> Malware
        # ----------------------------------------------------

        ["TA001", "USES_MALWARE", "MAL001"],
        ["TA002", "USES_MALWARE", "MAL002"],
        ["TA003", "USES_MALWARE", "MAL003"],
        ["TA004", "USES_MALWARE", "MAL004"],
        ["TA005", "USES_MALWARE", "MAL005"],


        # ----------------------------------------------------
        # Malware -> Vulnerability
        # ----------------------------------------------------

        ["MAL001", "EXPLOITS", "CVE-2026-1001"],
        ["MAL002", "EXPLOITS", "CVE-2026-1002"],
        ["MAL003", "EXPLOITS", "CVE-2026-1003"],
        ["MAL004", "EXPLOITS", "CVE-2026-1004"],
        ["MAL005", "EXPLOITS", "CVE-2026-1005"],


        # ----------------------------------------------------
        # Threat Actor -> Campaign
        # ----------------------------------------------------

        ["TA001", "ATTRIBUTED_TO_CAMPAIGN", "CAM001"],
        ["TA002", "ATTRIBUTED_TO_CAMPAIGN", "CAM002"],
        ["TA003", "ATTRIBUTED_TO_CAMPAIGN", "CAM003"],
        ["TA004", "ATTRIBUTED_TO_CAMPAIGN", "CAM004"],


        # ----------------------------------------------------
        # Campaign -> Organization
        # ----------------------------------------------------

        ["CAM001", "TARGETS", "ORG001"],
        ["CAM001", "TARGETS", "ORG005"],
        ["CAM002", "TARGETS", "ORG002"],
        ["CAM003", "TARGETS", "ORG003"],
        ["CAM004", "TARGETS", "ORG004"],


        # ----------------------------------------------------
        # Malware -> Domain
        # ----------------------------------------------------

        ["MAL001", "COMMUNICATES_WITH", "DOM001"],
        ["MAL002", "COMMUNICATES_WITH", "DOM002"],
        ["MAL003", "COMMUNICATES_WITH", "DOM003"],
        ["MAL004", "COMMUNICATES_WITH", "DOM004"],
        ["MAL005", "COMMUNICATES_WITH", "DOM005"],


        # ----------------------------------------------------
        # Domain -> IP Address
        # ----------------------------------------------------

        ["DOM001", "RESOLVES_TO", "IP001"],
        ["DOM002", "RESOLVES_TO", "IP002"],
        ["DOM003", "RESOLVES_TO", "IP003"],
        ["DOM004", "RESOLVES_TO", "IP004"],
        ["DOM005", "RESOLVES_TO", "IP005"],
    ],
    columns=[
        "source_id",
        "relationship",
        "target_id",
    ],
)


# ============================================================
# 10. SAVE DATASETS
# ============================================================

datasets = {
    "threat_actors.csv": threat_actors,
    "malware.csv": malware,
    "vulnerabilities.csv": vulnerabilities,
    "campaigns.csv": campaigns,
    "organizations.csv": organizations,
    "domains.csv": domains,
    "ip_addresses.csv": ip_addresses,
    "relationships.csv": relationships,
}


for filename, dataframe in datasets.items():

    output_file = DATA_DIR / filename

    dataframe.to_csv(
        output_file,
        index=False,
    )

    print(
        f"Created: {filename:<25}"
        f" Rows: {len(dataframe)}"
    )


# ============================================================
# 11. SUMMARY
# ============================================================

print("\n------------------------------------------")
print("Cybersecurity dataset successfully created")
print("------------------------------------------")

print(
    f"Total entity records: "
    f"{sum(len(df) for name, df in datasets.items() if name != 'relationships.csv')}"
)

print(
    f"Total relationships: {len(relationships)}"
)

print(
    f"\nDataset location:\n{DATA_DIR}"
)