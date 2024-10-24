# Service-Check-Scripts
This script monitors the health of an ArcGIS server, validates a datastore, and checks if any services are down. For GIS Admins.

Here is a description for each of the scripts you can use for your GitHub repository:

---

### 1. **generatekey_v0.1.py**

**Description**:  
This script generates and stores an encryption key using the `cryptography` library's `Fernet` encryption. It saves the key in a file called `secret.key` that can later be used to encrypt or decrypt sensitive data like passwords.

**Usage**:
1. Run this script to generate an encryption key.
2. The generated key is saved in a file named `secret.key`.
3. This key file should be securely stored and used for encryption/decryption in other scripts.

---

### 2. **encryptkey_v0.1.py**

**Description**:  
This script loads an encryption key from a file (`secret.key`) and uses it to encrypt a password. The encrypted password can replace the original plaintext password in a script for added security. It also scrambles the original password in the script after encryption.

**Usage**:
1. Update the variable `my_password` with your actual password before running.
2. The script encrypts the password and replaces it in the script with the scrambled version.
3. The encrypted password can be printed and used in other scripts for secure authentication.

**Note**: You need to have the `secret.key` file generated by the `generatekey_v0.1.py` script.

---

### 3. **prt_svr_ds_monitor_v0.1.py**

**Description**:  
This script monitors the health of an ArcGIS server, validates a datastore, and checks if any services are down. It uses the ArcGIS Server Admin API and performs checks to ensure the server and datastore are functioning as expected. In case of issues, it sends email alerts.

**Usage**:
1. Update the `admin_url`, `username`, `serverName`, `serverPort`, and email configuration before running.
2. The script logs server health and datastore validation issues, and it sends an email alert if any services are down or if there are validation errors.
3. The password is encrypted using the `Fernet` encryption, and the key is loaded from the `secret.key` file.

**Note**: Ensure you have the required API endpoints and permissions configured.

---

### 4. **prt_svr_ds_success_v0.1.py**

**Description**:  
This script is designed to check the health of an ArcGIS server, validate datastores, and check the status of ArcGIS services. It logs the results and sends an email alert if any issues are detected. It also decrypts an encrypted password using a key file (`secret.key`).

**Usage**:
1. Ensure the encryption key file (`secret.key`) exists and contains the key to decrypt the password.
2. Update the server credentials and email settings in the script.
3. The script logs the results of health checks and sends alerts for service failures or validation errors.

---

### 5. **scripts_test_v0.1.py**

**Description**:  
This script loads functions from another script (`prt_svr_ds_success_v1.1.py`) and allows the user to simulate various failure scenarios, such as server, portal, or datastore downtime. The script sends email alerts based on the simulated failure scenarios.

**Usage**:
1. Update the file path to point to the actual script you want to test.
2. The script provides a menu where you can select the type of failure (e.g., "Portal Down," "Server Down," etc.).
3. It logs the failure simulation and sends an email alert based on the selected scenario.

**Note**: This script is used for testing and simulating potential issues for failure handling.

---
