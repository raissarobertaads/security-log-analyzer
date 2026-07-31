from collections import Counter


def analyze_log(file_path):
    failed_attempts = []
    ip_addresses = []

    try:
        with open(file_path, "r") as file:
            for line in file:
                if "FAILED" in line:
                    parts = line.split()

                    if len(parts) >= 5:
                        ip = parts[4]
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

        print()
        print("=== SUSPICIOUS IP ADDRESSES ===")

        suspicious_found = False

        for ip, count in counter.items():
            if count >= 3:
                print(f"WARNING: {ip} has {count} failed attempts")
                suspicious_found = True

        if not suspicious_found:
            print("No suspicious IP addresses detected.")

    except FileNotFoundError:
        print("Log file not found.")


if __name__ == "__main__":
    analyze_log("security.log")
