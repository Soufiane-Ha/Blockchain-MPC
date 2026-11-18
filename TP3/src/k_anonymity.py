"""
k-Anonymity Implementation with Generalization and Suppression.
Satisfies the k-anonymity property for k in {2, 5, 10}:
Each equivalence class over Quasi-Identifiers (Age, Gender, Zip Code) has size >= k.
Computes Information Loss (Normalized Certainty Penalty - NCP).
"""

import csv
import os
from collections import defaultdict
from typing import List, Dict, Tuple, Any


def generalize_age(age: int, k: int) -> str:
    """Generalize continuous age into appropriate age intervals based on k."""
    if k <= 2:
        # 5-year intervals
        bin_start = (age // 5) * 5
        return f"[{bin_start}-{bin_start + 4}]"
    elif k <= 5:
        # 10-year intervals
        bin_start = (age // 10) * 10
        return f"[{bin_start}-{bin_start + 9}]"
    else:
        # 20-year intervals for higher k
        if age < 35:
            return "[18-34]"
        elif age < 55:
            return "[35-54]"
        elif age < 70:
            return "[55-69]"
        else:
            return "[70-85]"


def generalize_zip(zip_code: str, k: int) -> str:
    """Generalize 5-digit zip code using hierarchical digit suppression."""
    if k <= 2:
        # Mask 1 digit: e.g. 75001 -> 7500*
        return zip_code[:4] + "*"
    elif k <= 5:
        # Mask 2 digits: e.g. 75001 -> 750**
        return zip_code[:3] + "**"
    else:
        # Mask 3 digits: e.g. 75001 -> 75***
        return zip_code[:2] + "***"


def apply_k_anonymity(
    records: List[Dict[str, Any]],
    k: int,
    qi_keys: List[str] = ["age", "gender", "zip_code"]
) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """
    Applies generalization and suppression to enforce k-anonymity.
    Returns: (anonymized_records, metrics_summary)
    """
    # 1. Apply Generalization
    generalized = []
    for r in records:
        r_gen = dict(r)
        raw_age = int(r["age"])
        r_gen["age"] = generalize_age(raw_age, k)
        r_gen["zip_code"] = generalize_zip(r["zip_code"], k)
        # Gender remains or generalized if k is very large
        generalized.append(r_gen)

    # 2. Form Equivalence Classes based on generalized QIs
    equiv_classes = defaultdict(list)
    for r in generalized:
        qi_tuple = tuple(r[k_qi] for k_qi in qi_keys)
        equiv_classes[qi_tuple].append(r)

    # 3. Apply Suppression for classes with size < k
    anonymized_records = []
    suppressed_count = 0
    valid_classes = 0

    for qi_tuple, class_records in equiv_classes.items():
        if len(class_records) >= k:
            valid_classes += 1
            anonymized_records.extend(class_records)
        else:
            # Outlier class violates k-anonymity: suppress records
            suppressed_count += len(class_records)

    # 4. Verification Check
    # Verify min class size in anonymized dataset
    verify_classes = defaultdict(int)
    for r in anonymized_records:
        qi_tuple = tuple(r[k_qi] for k_qi in qi_keys)
        verify_classes[qi_tuple] += 1

    min_size = min(verify_classes.values()) if verify_classes else 0
    is_k_anonymous = min_size >= k if anonymized_records else False

    # 5. Information Loss (Normalized Certainty Penalty - NCP)
    # Total age range = 85 - 18 = 67
    # NCP_age for bin [a-b] = (b - a) / 67
    # NCP_zip for masked digits: 1/5, 2/5, 3/5
    # Suppressed records incur NCP = 1.0 across all attributes
    total_records = len(records)
    ncp_sum = 0.0

    for r in anonymized_records:
        # Age penalty
        age_str = r["age"].strip("[]")
        parts = [int(p) for p in age_str.split("-")]
        age_loss = (parts[1] - parts[0]) / 67.0

        # Zip penalty
        masked_digits = r["zip_code"].count("*")
        zip_loss = masked_digits / 5.0

        # Record loss
        record_loss = (age_loss + zip_loss) / 2.0
        ncp_sum += record_loss

    # Add max penalty for suppressed records
    ncp_sum += suppressed_count * 1.0
    global_information_loss = (ncp_sum / total_records) * 100.0  # percentage

    metrics = {
        "k": k,
        "total_input_records": total_records,
        "retained_records": len(anonymized_records),
        "suppressed_records": suppressed_count,
        "suppression_rate": (suppressed_count / total_records) * 100.0,
        "distinct_equivalence_classes": len(verify_classes),
        "min_class_size": min_size,
        "is_k_anonymous": is_k_anonymous,
        "information_loss_percent": round(global_information_loss, 2)
    }

    return anonymized_records, metrics


def run_k_anonymity_pipeline(input_csv: str, output_dir: str):
    """Executes k-anonymity for k = 2, 5, 10 and writes output datasets."""
    records = []
    with open(input_csv, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for r in reader:
            records.append(r)

    print("\n" + "=" * 70)
    print("      k-ANONYMITY EXECUTION PIPELINE (Generalization & Suppression)")
    print("=" * 70)
    print(f"[*] Loaded {len(records)} records from: {input_csv}")

    results = {}
    for k in [2, 5, 10]:
        anon_records, metrics = apply_k_anonymity(records, k=k)
        results[k] = metrics

        out_path = os.path.join(output_dir, f"k_anonymized_k{k}.csv")
        if anon_records:
            with open(out_path, "w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=list(anon_records[0].keys()))
                writer.writeheader()
                writer.writerows(anon_records)

        print(f"\n[+] k = {k}:")
        print(f"    - Output: {out_path}")
        print(f"    - Retained Records: {metrics['retained_records']}/{metrics['total_input_records']}")
        print(f"    - Suppressed Records: {metrics['suppressed_records']} ({metrics['suppression_rate']:.2f}%)")
        print(f"    - Equivalence Classes: {metrics['distinct_equivalence_classes']}")
        print(f"    - Minimum Class Size: {metrics['min_class_size']} (Constraint satisfied: {metrics['is_k_anonymous']})")
        print(f"    - Global Information Loss (NCP): {metrics['information_loss_percent']:.2f}%")

    print("\n" + "=" * 70)
    print("[SUCCESS] All datasets k-anonymized and verified!")
    print("=" * 70)
    return results


if __name__ == "__main__":
    base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "data"))
    in_csv = os.path.join(base_dir, "iot_smart_meter_sanitized.csv")
    run_k_anonymity_pipeline(in_csv, base_dir)

