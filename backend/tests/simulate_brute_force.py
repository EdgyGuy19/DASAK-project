"""
Simulates a brute force attack against /login to test detect_brute_force.
Runs against a local server.
"""
import sys
import time
import requests

TARGET = "http://127.0.0.1:8000"
assert TARGET.startswith("http://127.0.0.1"), "Only run against localhost"


def run_brute_force(username="testuser", attempts=10, delay=0.2):
    """Tries wrong passwords repeatedly against one account."""
    print(f"Starting brute force against '{username}' ({attempts} attempts)...")
    start = time.time()
    for i in range(attempts):
        res = requests.post(
            f"{TARGET}/login",
            json={"username": username, "password": f"wrong-password-{i}"},
        )
        print(f"  attempt {i + 1}: status {res.status_code}")
        time.sleep(delay)
    print(f"Done in {time.time() - start:.1f} seconds.")


def run_normal_traffic(username, password, attempts=2):
    """Simulates a couple of normal, legitimate login attempts."""
    print(f"Normal traffic for '{username}'...")
    for i in range(attempts):
        res = requests.post(
            f"{TARGET}/login",
            json={"username": username, "password": password},
        )
        print(f"  attempt {i + 1}: status {res.status_code}")


if __name__ == "__main__":
    mode = sys.argv[1] if len(sys.argv) > 1 else "attack"

    if mode == "attack":
        run_brute_force()
    elif mode == "normal":
        run_normal_traffic("alice", "wrong-password")
    else:
        print("Usage: python simulate_brute_force.py [attack|normal]")