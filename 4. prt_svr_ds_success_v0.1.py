import requests
import http.client as httplib
import urllib.parse
import json
import ssl
import datetime
import smtplib
import logging
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from cryptography.fernet import Fernet

# Set up logging
script_name = "Service_Check_Script"
log_filename = f"{script_name}.log"
logging.basicConfig(filename=log_filename, level=logging.INFO, format='%(asctime)s %(levelname)s:%(message)s')

# File path for the encryption key
secret_key_path = r"/path/to/secret.key"  # <--- Update this path

# Encrypted password (replace with your actual encrypted password)
encrypted_password = b'your-encrypted-password'  # <--- Replace with your encrypted password

# ArcGIS Server admin URL and credentials
admin_url = "https://your-gis-server/admin"  # <--- Update with your ArcGIS Server admin URL
username = "your-username"  # <--- Update with your username
serverName = "your-server-name"  # <--- Update with your server name
serverPort = 6443  # Change if necessary
folder = "root"  # Folder to check services in

# Email setup
def send_email(subject, body):
    smmFrom = "your-email@example.com"  # <--- Update with the sender's email
    SMTPMailRecpts = ["recipient1@example.com", "recipient2@example.com"]  # <--- Add recipients
    smmSvr = "your-smtp-server.com"  # <--- Update with your SMTP server
    
    msg = MIMEMultipart()
    msg['From'] = smmFrom
    msg['To'] = ", ".join(SMTPMailRecpts)
    msg['Subject'] = subject
    msg.attach(MIMEText(body, 'plain'))
    
    try:
        server = smtplib.SMTP(smmSvr, 25)
        server.sendmail(smmFrom, SMTPMailRecpts, msg.as_string())
        server.quit()
        logging.info(f"Email sent successfully with subject: {subject}")
    except Exception as e:
        logging.error(f"Failed to send email: {e}")

# Function to load the encryption key
def load_key():
    return open(secret_key_path, "rb").read()

# Function to decrypt the password
def decrypt_password(encrypted_password):
    key = load_key()
    fernet = Fernet(key)
    decrypted_password = fernet.decrypt(encrypted_password).decode()
    return decrypted_password

# Get token for authentication
def get_token(username, decrypted_password, serverName, serverPort):
    tokenURL = "/arcgis/admin/generateToken"
    params = urllib.parse.urlencode({
        'username': username,
        'password': decrypted_password,
        'client': 'requestip',
        'f': 'json'
    })
    headers = {"Content-type": "application/x-www-form-urlencoded", "Accept": "text/plain"}

    try:
        httpConn = httplib.HTTPSConnection(serverName, serverPort, context=ssl._create_unverified_context())
        httpConn.request("POST", tokenURL, params, headers)
        response = httpConn.getresponse()
        if response.status != 200:
            logging.error("Error fetching token.")
            return ""
        else:
            data = response.read()
            token = json.loads(data)
            logging.info("Token fetched successfully.")
            return token['token']
    except Exception as e:
        logging.error(f"Error fetching token: {e}")
        return ""

# Validate datastore and return results
def validate_datastore(admin_url, token):
    headers = {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Authorization': f'Bearer {token}'
    }
    validate_url = f"{admin_url}/data/items/enterpriseDatabases/AGSDataStore_ds_qxb70fyl/machines/your-datastore-machine/validate?f=pjson"  # <--- Update with your datastore machine

    try:
        response = requests.post(validate_url, headers=headers, verify=False)
        if response.status_code == 200:
            return response.json()
        else:
            logging.error(f"Failed to validate datastore: {response.text}")
            return f"Failed to validate datastore: {response.text}"
    except requests.exceptions.RequestException as e:
        logging.error(f"Error validating datastore: {e}")
        return f"Error validating datastore: {e}"

# Check datastore validation and return issues if found
def check_conditions(datastore_info):
    try:
        machine_info = datastore_info['machines'][0]
    except (IndexError, KeyError):
        logging.error("Error: No machines found in the datastore response.")
        return "Error: No machines found in the datastore response."

    issues = []

    if machine_info.get("machine.isReachable") != "true":
        issues.append("Machine is not reachable.")
    if machine_info.get("machine.overallhealth") != "Healthy":
        issues.append("Machine health is not 'Healthy'.")
    if machine_info.get("db.isactive") != "true":
        issues.append("DB is not active.")
    if machine_info.get("db.isAccepting") != "true":
        issues.append("DB is not accepting connections.")

    return "\n".join(issues) if issues else "Datastore validation passed successfully."

# Check server health and return results
def check_server_health():
    url = "https://your-server-name/arcgis/datastore"  # <--- Update with your server health check URL
    try:
        response = requests.get(url, timeout=5, verify=False)
        if response.status_code == 200:
            logging.info("Server health check passed successfully.")
            return "Server health check passed successfully."
        else:
            logging.warning(f"Warning: Server responded with status code {response.status_code}.")
            return f"Warning: Server responded with status code {response.status_code}."
    except requests.exceptions.RequestException as e:
        logging.error(f"Error: Could not reach the server. Exception: {e}")
        return f"Error: Could not reach the server. Exception: {e}"

# Check services and return report if any services are stopped
def check_services(token, serverName, serverPort, folder):
    stoppedList = []
    folder = "" if str.upper(folder) == "ROOT" else folder + "/"
    folderURL = f"/arcgis/admin/services/{folder}"
    params = urllib.parse.urlencode({'token': token, 'f': 'json'})
    headers = {"Content-type": "application/x-www-form-urlencoded", "Accept": "text/plain"}

    try:
        httpConn = httplib.HTTPSConnection(serverName, serverPort, context=ssl._create_unverified_context())
        httpConn.request("POST", folderURL, params, headers)
        response = httpConn.getresponse()
        if response.status != 200:
            httpConn.close()
            logging.error("Could not read folder information.")
            return "Could not read folder information."
        else:
            data = response.read()
            dataObj = json.loads(data)
            httpConn.close()

            for item in dataObj['services']:
                fullSvcName = f"{item['serviceName']}.{item['type']}"
                statusURL = f"/arcgis/admin/services/{folder}{fullSvcName}/status"
                httpConn.request("POST", statusURL, params, headers)
                statusResponse = httpConn.getresponse()
                if statusResponse.status != 200:
                    logging.error(f"Error while checking status for {fullSvcName}")
                else:
                    statusData = statusResponse.read()
                    statusDataObj = json.loads(statusData)
                    if statusDataObj['realTimeState'] == "STOPPED":
                        stoppedList.append([fullSvcName, str(datetime.datetime.now())])
                httpConn.close()

    except Exception as e:
        logging.error(f"Error checking services: {e}")
        return f"Error checking services: {e}"

    if not stoppedList:
        logging.info("All services are running normally.")
        return "All services are running normally."
    else:
        service_status_report = "Stopped services detected:\n"
        for item in stoppedList:
            service_status_report += f"Service {item[0]} was detected to be stopped at {item[1]}\n"
        logging.warning(f"Stopped services detected: {service_status_report}")
        return service_status_report

if __name__ == "__main__":

    try:
        logging.info("Script execution started.")

        # Decrypt the password before running the checks
        decrypted_password = decrypt_password(encrypted_password)

        # Check existing server health
        server_health_issue = check_server_health()

        # Generate token
        token = get_token(username, decrypted_password, serverName, serverPort)

        # Validate datastore and check for issues
        datastore_report = validate_datastore(admin_url, token)
        if isinstance(datastore_report, str):
            datastore_issues = datastore_report
        else:
            datastore_issues = check_conditions(datastore_report)

        # Check for stopped services
        service_status_report = check_services(token, serverName, serverPort, folder)

        # Compile the full results for notification
        email_body = (
            f"Server Health: {server_health_issue}\n\n"
            f"Datastore Validation: {datastore_issues}\n\n"
            f"ArcGIS Server services Status: {service_status_report}"
        )

        # Send notification with the full results
        send_email("GeoState Portal, Data Store, and Service Status Results", email_body)

        logging.info("Script executed successfully.")
    except requests.exceptions.RequestException as e:
        # Handle the case where the server is not reachable (e.g., [WinError 10060])
        error_message = f"An error occurred during execution: {e}\n\nIt appears that Portal, Server, and DataStore might be down."
        logging.error(error_message)
        send_email("GeoState Critical Alert: Services Down", error_message)

    except Exception as e:
        logging.error(f"Script execution failed: {e}")
        send_email("Script Error", f"An error occurred during execution: {e}")


   
