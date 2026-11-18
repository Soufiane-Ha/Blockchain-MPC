"""
Differential Privacy Implementation for IoT Aggregate Queries.
Implements the Laplace Mechanism for epsilon in {0.1, 1.0, 10.0} and measures
the privacy-utility trade-off (Mean Absolute Error and Relative Error).
"""

import csv
import math
import os
import random
from typing import List, Dict, Tuple
import numpy as np


def laplace_mechanism(true_value: float, sensitivity: float, epsilon: float) -> float:
    """
    Applies the Laplace mechanism to achieve epsilon-Differential Privacy:
    Noise ~ Lap(scale = sensitivity / epsilon).
    """
    if epsilon <= 0:
        raise ValueError("Epsilon must be strictly positive.")
    scale = sensitivity / epsilon
    # Sample from Laplace distribution using inverse transform
    u = random.uniform(-0.5, 0.5)
    noise = -math.copysign(1.0, u) * scale * math.log(1.0 - 2.0 * abs(u))
    return true_value + noise


def evaluate_dp_queries(
    dataset_path: str,
    epsilons: List[float] = [0.1, 1.0, 10.0],
    num_trials: int = 500
) -> Dict[str, Any]:
    """
    Runs aggregate queries with the Laplace mechanism over multiple trials
    to empirically measure privacy vs. accuracy (utility).
    """
    # 1. Load IoT consumption data
    consumptions = []
    medical_counts = 0
    with open(dataset_path, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for r in reader:
            val = float(r["hourly_consumption_kwh"])
            consumptions.append(val)
            if r["medical_equipment_active"] == "Yes":
                medical_counts += 1

    N = len(consumptions)
    min_val = min(consumptions)
    max_val = max(consumptions)

    # 2. Query 1: Average hourly consumption
    # True mean
    true_mean = sum(consumptions) / N
    # Global Sensitivity for Mean = (max - min) / N
    mean_sensitivity = (max_val - min_val) / N

    # 3. Query 2: Total Grid Consumption (Sum)
    true_sum = sum(consumptions)
    sum_sensitivity = max_val - min_val

    # 4. Query 3: Count of sensitive households (medical equipment active)
    true_count = medical_counts
    count_sensitivity = 1.0

    print("\n" + "=" * 75)
    print("      DIFFERENTIAL PRIVACY EVALUATION (Laplace Mechanism)")
    print("=" * 75)
    print(f"[*] Dataset Size: N = {N}")
    print(f"[*] Hourly Consumption Range: [{min_val:.2f}, {max_val:.2f}] kWh")
    print(f"[*] Query 1 (Average Consumption): True Value = {true_mean:.4f} kWh | Sensitivity Δf = {mean_sensitivity:.6f}")
    print(f"[*] Query 2 (Total Consumption):   True Value = {true_sum:.2f} kWh  | Sensitivity Δf = {sum_sensitivity:.4f}")
    print(f"[*] Query 3 (Medical Count):       True Value = {true_count} homes    | Sensitivity Δf = {count_sensitivity:.1f}")

    results = {
        "dataset_size": N,
        "true_mean": true_mean,
        "true_sum": true_sum,
        "true_count": true_count,
        "mean_sensitivity": mean_sensitivity,
        "epsilons": {}
    }

    print("\n" + "-" * 75)
    print(f"{'Epsilon (ε)':<12} | {'Mean Noisy Ans':<16} | {'Empirical MAE':<15} | {'Theoretical MAE':<16} | {'Rel Error (%)'}")
    print("-" * 75)

    for eps in epsilons:
        noisy_means = []
        errors = []
        for _ in range(num_trials):
            noisy_val = laplace_mechanism(true_mean, mean_sensitivity, eps)
            noisy_means.append(noisy_val)
            errors.append(abs(noisy_val - true_mean))

        emp_mae = sum(errors) / num_trials
        theo_mae = mean_sensitivity / eps
        rel_error = (emp_mae / true_mean) * 100.0
        avg_noisy = sum(noisy_means) / num_trials

        results["epsilons"][eps] = {
            "avg_noisy_answer": avg_noisy,
            "empirical_mae": emp_mae,
            "theoretical_mae": theo_mae,
            "relative_error_pct": rel_error
        }

        print(f"{eps:<12} | {avg_noisy:<16.4f} | {emp_mae:<15.6f} | {theo_mae:<16.6f} | {rel_error:<10.3f}%")

    print("-" * 75)
    print("[ANALYSIS]")
    print("  - ε = 0.1  : High Privacy (strong noise), error ~ {:.4f} kWh ({:.2f}% rel error).".format(
        results["epsilons"][0.1]["empirical_mae"], results["epsilons"][0.1]["relative_error_pct"]))
    print("  - ε = 1.0  : Balanced Privacy/Utility, error ~ {:.5f} kWh ({:.3f}% rel error).".format(
        results["epsilons"][1.0]["empirical_mae"], results["epsilons"][1.0]["relative_error_pct"]))
    print("  - ε = 10.0 : Low Privacy (negligible noise), error ~ {:.6f} kWh ({:.4f}% rel error).".format(
        results["epsilons"][10.0]["empirical_mae"], results["epsilons"][10.0]["relative_error_pct"]))
    print("=" * 75)

    return results


if __name__ == "__main__":
    data_file = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "data", "iot_smart_meter_sanitized.csv"))
    evaluate_dp_queries(data_file)

