"""
Linkage Attack Demonstration (Re-identification Attack).
Demonstrates how an adversary can re-identify individuals in a de-identified
IoT dataset by joining Quasi-Identifiers (QI: Age, Gender, Zip Code) with an external
public registry (e.g., Voter Registry).
"""

import csv
import os
from collections import defaultdict


def perform_linkage_attack(sanitized_path: str, voter_path: str, max_display: int = 5):
    """
    Performs a linkage attack by matching Quasi-Identifiers (QI) between
    the sanitized IoT dataset and the public voter registry.
    """
    print("\n" + "=" * 70)
    print("      LINKAGE ATTACK SIMULATION (Sweeney's Re-Identification)")
    print("=" * 70)

    # 1. Load Sanitized IoT Records
    iot_records = []
    with open(sanitized_path, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            iot_records.append(row)

    # 2. Load Public Voter Registry Records
    voter_records = []
    with open(voter_path, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            voter_records.append(row)

    total_iot = len(iot_records)
    total_voters = len(voter_records)
    print(f"[*] Loaded {total_iot} sanitized IoT records.")
    print(f"[*] Loaded {total_voters} public voter registry records.")
    print("[*] Target Quasi-Identifiers (QI): (Age, Gender, Zip Code)")

    # 3. Index Voter Records by Quasi-Identifier tuple
    # QI tuple = (age, gender, zip_code)
    voter_qi_map = defaultdict(list)
    for v in voter_records:
        qi = (v["age"], v["gender"], v["zip_code"])
        voter_qi_map[qi].append(v)

    # 4. Attempt Linkage
    unique_matches = []
    ambiguous_matches = []
    unmatched = 0

    for idx, iot in enumerate(iot_records):
        qi = (iot["age"], iot["gender"], iot["zip_code"])
        matches = voter_qi_map.get(qi, [])

        if len(matches) == 1:
            # Exactly one match -> 100% Unique Re-Identification!
            unique_matches.append((iot, matches[0]))
        elif len(matches) > 1:
            ambiguous_matches.append((iot, matches))
        else:
            unmatched += 1

    reid_rate = (len(unique_matches) / total_iot) * 100

    print("\n--- ATTACK RESULTS SUMMARY ---")
    print(f"Total IoT Records Analyzed:     {total_iot}")
    print(f"Uniquely Re-identified Victims: {len(unique_matches)} ({reid_rate:.2f}%)")
    print(f"Ambiguous Matches (>1 match):   {len(ambiguous_matches)}")
    print(f"Unmatched:                      {unmatched}")

    print("\n--- TOP RE-IDENTIFIED VICTIMS (CONCRETE PRIVACY BREACH) ---")
    for i, (iot, voter) in enumerate(unique_matches[:max_display]):
        print(f"\n[!] VICTIM #{i + 1}:")
        print(f"    - Full Name (from Voter Reg): {voter['full_name']}")
        print(f"    - Address (from Voter Reg):   {voter['home_address']}, {voter['city']}")
        print(f"    - Leaked Quasi-Identifiers:  Age={iot['age']}, Gender={iot['gender']}, Zip={iot['zip_code']}")
        print(f"    - Compromised Sensitive IoT Data:")
        print(f"        * Hourly Consumption:     {iot['hourly_consumption_kwh']} kWh")
        print(f"        * Peak Usage Time:        {iot['peak_usage_time']}")
        print(f"        * Occupancy Habit:        {iot['occupancy_status']}")
        print(f"        * Medical Device Active:  {iot['medical_equipment_active']}")

    print("\n" + "=" * 70)
    print("[CONCLUSION] Naive de-identification (removing names/IDs) fails completely!")
    print(f"             Adversary re-identified {reid_rate:.2f}% of users simply by combining QIs.")
    print("=" * 70)

    return {
        "total_records": total_iot,
        "unique_matches": len(unique_matches),
        "reid_rate": reid_rate,
        "ambiguous_matches": len(ambiguous_matches),
        "unmatched": unmatched
    }


if __name__ == "__main__":
    base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "data"))
    sanitized_csv = os.path.join(base_dir, "iot_smart_meter_sanitized.csv")
    voter_csv = os.path.join(base_dir, "voter_registry.csv")

    perform_linkage_attack(sanitized_csv, voter_csv)

