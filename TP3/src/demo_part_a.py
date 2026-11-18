"""
Part A Unified Runner: IoT Dataset Anonymization & Attack Evaluation.
Runs all steps of Part A:
1. Dataset generation
2. Linkage Re-identification Attack demonstration
3. k-Anonymity execution (k=2, 5, 10)
4. Differential Privacy queries (eps=0.1, 1.0, 10.0)
5. Benchmarking and Plot generation
"""

import os
import sys

from dataset_generator import generate_datasets
from linkage_attack import perform_linkage_attack
from k_anonymity import run_k_anonymity_pipeline
from differential_privacy import evaluate_dp_queries
from benchmark_privacy import run_benchmarks


def main():
    base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    data_dir = os.path.join(base_dir, "data")
    results_dir = os.path.join(base_dir, "results")

    print("\n" + "#" * 80)
    print("      TP3 - PART A: IOT DATASET ANONYMIZATION & PRIVACY EXPERIMENTS")
    print("#" * 80)

    # Step 1: Generate datasets
    print("\n>>> STEP 1: Generating IoT Dataset and Public Voter Registry...")
    generate_datasets(data_dir, num_records=1000)

    # Step 2: Perform Linkage Attack on Sanitized data
    print("\n>>> STEP 2: Executing Linkage Re-identification Attack...")
    sanitized_csv = os.path.join(data_dir, "iot_smart_meter_sanitized.csv")
    voter_csv = os.path.join(data_dir, "voter_registry.csv")
    perform_linkage_attack(sanitized_csv, voter_csv, max_display=3)

    # Step 3: Apply k-Anonymity
    print("\n>>> STEP 3: Applying k-Anonymity (k=2, 5, 10) with Generalization & Suppression...")
    run_k_anonymity_pipeline(sanitized_csv, data_dir)

    # Step 4: Differential Privacy
    print("\n>>> STEP 4: Evaluating Differential Privacy with Laplace Mechanism...")
    evaluate_dp_queries(sanitized_csv, epsilons=[0.1, 1.0, 10.0], num_trials=500)

    # Step 5: Benchmarking & Plots
    print("\n>>> STEP 5: Benchmarking Privacy vs Utility & Generating Graphs...")
    run_benchmarks(data_dir, results_dir)

    print("\n" + "#" * 80)
    print("      PART A COMPLETED SUCCESSFULLY! ALL DELIVERABLES GENERATED.")
    print("#" * 80)


if __name__ == "__main__":
    main()

