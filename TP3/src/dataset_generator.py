"""
IoT Smart-Meter Dataset and Public Registry Generator.
Generates realistic datasets for privacy and anonymization experiments:
1. IoT Smart-Meter Dataset (Direct IDs, Quasi-Identifiers, Sensitive Attributes)
2. Public Voter Registry (for Linkage Re-identification Attacks)
"""

import csv
import os
import random

FIRST_NAMES = [
    "Alice", "Bob", "Carol", "Dave", "Eve", "Frank", "Grace", "Heidi",
    "Ivan", "Judy", "Mallory", "Niaj", "Oscar", "Peggy", "Rupert", "Sybil",
    "Trent", "Victor", "Walter", "Yvonne", "Arthur", "Béatrice", "Cédric",
    "Diane", "Émile", "Fanny", "Gérard", "Hélène", "Isabelle", "Julien",
    "Karim", "Leila", "Mehdi", "Nadia", "Omar", "Rachid", "Samira", "Tariq",
    "Yacine", "Zineb", "Ahmed", "Fatima", "Mohamed", "Amine", "Sarah", "Kenza"
]

LAST_NAMES = [
    "Smith", "Johnson", "Williams", "Brown", "Jones", "Garcia", "Miller",
    "Davis", "Rodriguez", "Martinez", "Hernandez", "Lopez", "Gonzalez",
    "Wilson", "Anderson", "Thomas", "Taylor", "Moore", "Jackson", "Martin",
    "Dupont", "Durand", "Lefebvre", "Moreau", "Laurent", "Simon", "Michel",
    "Benali", "Mansouri", "Cherif", "Brahimi", "Saidi", "Hamdi", "Kacemi"
]

ZIP_CODES = [
    "75001", "75002", "75003", "75004", "75005", "75006", "75007", "75008",
    "69001", "69002", "69003", "13001", "13002", "31000", "59000", "44000"
]

CITIES = {
    "75001": "Paris", "75002": "Paris", "75003": "Paris", "75004": "Paris",
    "75005": "Paris", "75006": "Paris", "75007": "Paris", "75008": "Paris",
    "69001": "Lyon",  "69002": "Lyon",  "69003": "Lyon",
    "13001": "Marseille", "13002": "Marseille",
    "31000": "Toulouse", "59000": "Lille", "44000": "Nantes"
}

PEAK_HOURS = [
    "07:00-09:00", "12:00-14:00", "18:00-20:00", "20:00-22:00", "23:00-02:00"
]

OCCUPANCY = ["At Home", "At Work", "Away/Vacation", "Night Shift"]


def generate_datasets(data_dir: str, num_records: int = 1000, seed: int = 42):
    random.seed(seed)
    os.makedirs(data_dir, exist_ok=True)

    raw_path = os.path.join(data_dir, "iot_smart_meter_raw.csv")
    sanitized_path = os.path.join(data_dir, "iot_smart_meter_sanitized.csv")
    voter_path = os.path.join(data_dir, "voter_registry.csv")

    records = []
    voter_records = []

    for i in range(1, num_records + 1):
        fn = random.choice(FIRST_NAMES)
        ln = random.choice(LAST_NAMES)
        full_name = f"{fn} {ln}"
        user_id = f"USR-{10000 + i}"
        national_id = f"NID-{random.randint(10000000, 99999999)}"
        mac = ":".join(f"{random.randint(0, 255):02X}" for _ in range(6))

        # Quasi-Identifiers
        age = random.randint(18, 85)
        gender = random.choice(["M", "F"])
        zip_code = random.choice(ZIP_CODES)
        city = CITIES[zip_code]

        # Sensitive attributes
        # Hourly consumption in kWh (e.g. 0.2 to 8.5 kWh)
        base_cons = random.uniform(0.3, 4.0)
        # Add spikes for users with medical equipment or heating
        has_medical = random.random() < 0.08  # 8% of users
        if has_medical:
            base_cons += random.uniform(2.5, 4.5)
        hourly_kwh = round(base_cons, 2)
        peak_hour = random.choice(PEAK_HOURS)
        occupancy = random.choice(OCCUPANCY)

        records.append({
            "user_id": user_id,
            "full_name": full_name,
            "national_id": national_id,
            "mac_address": mac,
            "age": age,
            "gender": gender,
            "zip_code": zip_code,
            "city": city,
            "hourly_consumption_kwh": hourly_kwh,
            "peak_usage_time": peak_hour,
            "occupancy_status": occupancy,
            "medical_equipment_active": "Yes" if has_medical else "No"
        })

        # Auxiliary dataset (Public Voter / Resident Registry)
        # Includes public identity + quasi-identifiers
        voter_records.append({
            "voter_id": f"VOTE-{50000 + i}",
            "full_name": full_name,
            "age": age,
            "gender": gender,
            "zip_code": zip_code,
            "city": city,
            "home_address": f"{random.randint(1, 250)} Rue Principale"
        })

    # 1. Write raw IoT smart meter dataset
    with open(raw_path, "w", newline="", encoding="utf-8") as f:
        fieldnames = [
            "user_id", "full_name", "national_id", "mac_address",
            "age", "gender", "zip_code", "city",
            "hourly_consumption_kwh", "peak_usage_time", "occupancy_status", "medical_equipment_active"
        ]
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(records)

    # 2. Write sanitized (naively de-identified) IoT smart meter dataset (Direct IDs removed)
    with open(sanitized_path, "w", newline="", encoding="utf-8") as f:
        fieldnames = [
            "age", "gender", "zip_code", "city",
            "hourly_consumption_kwh", "peak_usage_time", "occupancy_status", "medical_equipment_active"
        ]
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for r in records:
            writer.writerow({k: r[k] for k in fieldnames})

    # 3. Write public voter registry
    with open(voter_path, "w", newline="", encoding="utf-8") as f:
        fieldnames = ["voter_id", "full_name", "age", "gender", "zip_code", "city", "home_address"]
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(voter_records)

    print(f"[+] Successfully generated {num_records} IoT records:")
    print(f"    - Raw IoT dataset: {raw_path}")
    print(f"    - Sanitized IoT dataset (Direct IDs removed): {sanitized_path}")
    print(f"    - Public Voter Registry: {voter_path}")


if __name__ == "__main__":
    target_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "data"))
    generate_datasets(target_dir, num_records=1000)

