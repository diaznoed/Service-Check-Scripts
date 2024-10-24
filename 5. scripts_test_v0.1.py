import importlib.util
import logging
from datetime import datetime

# Set up logging with a timestamp in the filename
script_name = "Test_Scripts_Alerts"
current_time = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
log_filename = f"{script_name}_{current_time}.log"

logging.basicConfig(filename=log_filename, level=logging.INFO, format='%(asctime)s %(levelname)s:%(message)s')

# Path to your file with non-standard name
file_path = '/path/to/4. prt_svr_ds_success_v1.1.py'  # <--- Update with the actual path

# Load module from the given path
spec = importlib.util.spec_from_file_location("prt_svr_ds_success_v1", file_path)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

# Now you can access the functions from the imported script
send_email = module.send_email
check_server_health = module.check_server_health
check_services = module.check_services
validate_datastore = module.validate_datastore
decrypt_password = module.decrypt_password
get_token = module.get_token

# Logging setup for the test script (logs to console)
logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s:%(message)s')

# Simulation function to "mock" failures
def simulate_failure(service_name):
    if service_name == "portal":
        logging.info("Simulating Portal down...")
        return "Error: Portal is not reachable. Service might be down."
    elif service_name == "server":
        logging.info("Simulating Server down...")
        return "Error: Server is not reachable. Service might be down."
    elif service_name == "datastore":
        logging.info("Simulating Datastore down...")
        return "Error: Datastore is not reachable. Service might be down."
    elif service_name == "all":
        logging.info("Simulating All services down...")
        return "Error: Portal, Server, and Datastore are not reachable. All services might be down."
    else:
        return None

# Test function for running scenarios
def run_test_scenario(services_down):
    logging.info(f"Running test scenario with the following services down: {services_down}")
    
    # Simulate different services being down
    email_body = ""
    
    if "portal" in services_down:
        # Simulate portal failure
        portal_health_issue = simulate_failure("portal")
        email_body += f"Portal Health: {portal_health_issue}\n\n"
    
    if "server" in services_down:
        # Simulate server failure
        server_health_issue = simulate_failure("server")
        email_body += f"Server Health: {server_health_issue}\n\n"
    
    if "datastore" in services_down:
        # Simulate datastore failure
        datastore_health_issue = simulate_failure("datastore")
        email_body += f"Datastore Health: {datastore_health_issue}\n\n"
    
    # Check if we need to simulate all services down
    if "all" in services_down:
        all_services_down = simulate_failure("all")
        email_body = f"Services Health: {all_services_down}\n\n"
    
    # Send simulated email alert
    send_email("GeoState Service Test Alert", email_body)

if __name__ == "__main__":
    # Define scenarios to test
    # Possible values: "portal", "server", "datastore", "all"
    
    print("Select a test scenario to simulate:")
    print("1. Only Portal Down")
    print("2. Only Server Down")
    print("3. Only Datastore Down")
    print("4. All Services Down")
    
    choice = input("Enter your choice (1-4): ")
    
    if choice == "1":
        run_test_scenario(["portal"])
    elif choice == "2":
        run_test_scenario(["server"])
    elif choice == "3":
        run_test_scenario(["datastore"])
    elif choice == "4":
        run_test_scenario(["all"])
    else:
        print("Invalid choice! Please select a valid scenario.")
