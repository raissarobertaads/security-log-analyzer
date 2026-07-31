from collections import Counter


def analyze_log(file_path):
    failed_attempts = []
    ip_addresses = []

    try:
        with open(file_path, "r") as file:
            for line in file:
                if "FAILED" in line:
                    parts = line.split()

                    if len(parts) >= 4:
                        ip = parts[3]
                        failed_attempts.append(ip)
                        ip_addresses.append(ip)

        print("=== SECURITY LOG ANALYZER ===")
        print()

        print(f"Total de failed login attempts: {len(failed_attempts)}")
        print()

        print("Attempts by IP:")
        counter = Counter(ip_addresses)

        for ip, count in counter.items():
            print(f"{ip}: {count} attempts")

    except FileNotFoundError:
        print("Log file not found.")


if __name__ == "__main__":
    analyze_log("security.log")
