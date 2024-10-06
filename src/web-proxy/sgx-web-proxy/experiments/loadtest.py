import requests
import time
import concurrent.futures
import numpy as np
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Configuration
target_url = "https://localhost:8081?url=example.com"
#target_url = "https://localhost:8081?url=syssec.ethz.ch"
initial_clients = 5
max_clients = 111  # Set the maximum number of clients you want to test with
increment = 5  # Increase the number of clients by this number each iteration
iterations = (max_clients - initial_clients) // increment + 1

# Function to simulate a client making a request through the proxy
def simulate_client(args):
    try:
        start_time = time.time()
        response = requests.get(target_url, verify=False, timeout=10)
        # print(response.text)
        response_time = time.time() - start_time
        return response_time, response.status_code == 200
    except Exception as e:
        return None, False

# Function to run the test for a given number of clients
def run_test(num_clients):
    with concurrent.futures.ThreadPoolExecutor(max_workers=num_clients) as executor:
        results = list(executor.map(simulate_client, range(num_clients)))

    response_times = [result[0] for result in results if result[0] is not None]
    success_count = sum([1 for result in results if result[1]])
    fail_count = num_clients - success_count

    if response_times:
        avg_time = np.mean(response_times)
        stddev_time = np.std(response_times)
    else:
        avg_time = None
        stddev_time = None

    return avg_time, stddev_time, fail_count

# Main testing loop
def main():
    for i in range(iterations):
        num_clients = initial_clients + i * increment
        avg_time, stddev_time, fail_count = run_test(num_clients)
        print(f"Clients: {num_clients}, Avg Time: {avg_time}, Stddev Time: {stddev_time}, Failed: {fail_count}")


if __name__ == "__main__":
    main()
