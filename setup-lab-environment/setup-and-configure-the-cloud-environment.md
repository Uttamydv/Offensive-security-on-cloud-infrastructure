In this project, the creation of an AWS (Amazon Web Services) account serves as the foundational
step for building a realistic cloud infrastructure environment to conduct offensive security
assessments. AWS is a widely adopted cloud platform that provides scalable computing resources,
storage services, and network configurations—making it ideal for simulating enterprise-grade cloud
environments. By setting up a dedicated AWS account, we can securely deploy and isolate various
cloud components such as EC2 instances, S3 buckets, IAM users, and VPCs to mimic real-world
infrastructure. This allows us to intentionally configure insecure settings and simulate potential
attack surfaces—such as privilege escalation, public data exposure, and insecure network
architectures—thus enabling hands-on exploration of vulnerabilities and testing the effectiveness of
offensive security techniques in a controlled and legal cloud environment.

---

## 5.1 AWS Account Creation and IAM Configuration

The initial step involved setting up a dedicated AWS account, which serves as the isolated environment for all subsequent resource deployments and offensive security assessments.

### Step 1: AWS Account Creation

1.  **Go to AWS Portal:** Visit `https://aws.amazon.com` and click on "Create an AWS Account."

![Screenshot From 2025-06-18 18-16-16](https://github.com/user-attachments/assets/34d04306-4b8d-45d2-8034-6be9e78d5caf)

2.  **Provide Basic Information:**
    * Set a **unique** email address.
    * Choose an AWS account name (e.g., `project-offensive-security-lab`).
    * Set a **strong** password.

![Screenshot From 2025-06-18 18-18-58](https://github.com/user-attachments/assets/0bdb5db3-580f-4b30-867c-0b0b92a6d0ee)

3.  **Account Type:** Select "Personal" for lab/testing purposes.
4.  **Billing Information:** Enter valid credit/debit card details. AWS uses this for identity verification and billing for usage beyond the free tier.
5.  **Phone Number Verification:** Complete the phone verification process.
6.  **Select a Support Plan:** Choose the "Basic Support Plan" (which is free-tier compatible).
7.  **Account Created!** Once confirmed, proceed to log in.
8.  **Login:** Access the AWS Management Console using the root account credentials (email and password).

![Screenshot From 2025-06-18 18-19-59](https://github.com/user-attachments/assets/06c3f637-d493-4aa5-9f11-7b743a21ca73)


### Step 2: Enable MFA for Root User (Important Security Practice)

Enabling Multi-Factor Authentication for the root user is a critical security best practice to protect the most privileged account in your AWS environment.

1.  **Navigate to IAM:** From the AWS Console, go to **IAM** > **Users** > **Root User**.
2.  **Enable Multi-Factor Authentication (MFA):**
    * Select "Virtual MFA device" (e.g., Google Authenticator, Duo Mobile) or a hardware key.
    * For this project, **Duo Mobile App** was used, requiring a passcode from the MFA device for every root account login.

![Screenshot From 2025-06-18 18-23-10](https://github.com/user-attachments/assets/4c8a3276-c2d2-4402-9b54-dad09f5386ea)


### Step 3: IAM User Creation (Misconfiguration Area)

This step involved creating an IAM user with deliberately excessive permissions to serve as a target for privilege escalation demonstrations.

1.  **Navigate to IAM Console:** Search for "IAM" in the AWS Console search bar.

![Screenshot From 2025-06-18 18-24-37](https://github.com/user-attachments/assets/8cfc2a3e-e413-4fb7-aa58-2ea84616d123)

2.  **Create User:** Create a new user (e.g., `test-user`).
    * Enable "Programmatic access" (for CLI/API interactions).
    * Optionally enable "AWS Management Console access" for console logins.
3.  **Assign Permissions (Intentional Misconfiguration):**
    * **Directly attach the `AdministratorAccess` policy.** This is a highly insecure practice in real-world scenarios but is critical for demonstrating privilege escalation in this lab.
    * (Alternatively for other tests): Create a group with an over-permissioned custom policy and add the user to this group.
4.  **Set Tags (Optional):** Add relevant tags for organization.
5.  **Review & Create:** **Crucially, save the Access Key ID and Secret Access Key** provided after creation. These are needed for CLI access and will be used as the "exposed" credentials in later attack simulations.

![Screenshot From 2025-06-18 18-25-48](https://github.com/user-attachments/assets/4e4874e0-f193-49ea-af85-26dc8f263181)


---

## 5.2 Deployment of Misconfigured Cloud Resources and Services

Following the AWS account and IAM setup, various cloud resources were manually provisioned and intentionally misconfigured to simulate common security oversights in a real-world infrastructure.

### Step 1: Create a Virtual Private Cloud (VPC)

The VPC provides a private, isolated network environment within AWS for launching and managing resources securely.

**VPC Components:**
* **Subnets:** Smaller, segmented parts of a larger network that isolate and organize devices within the VPC.
* **Route Table:** A set of rules determining where network traffic from a subnet or gateway is directed.
* **Internet Gateway (IGW):** Allows communication between instances in your subnets/VPC and the internet.
* **Security Groups:** Instance-specific network firewall rules that control inbound and outbound traffic (allow rules only).
* **Network ACL (NACL):** An optional, subnet-specific layer of security acting as a firewall for controlling traffic in and out of one or more subnets (allows both allow and deny rules).

**Manual VPC Creation Steps:**
* A custom VPC named `my-personal-vpc` was created with a CIDR block of `10.0.0.0/16`.

![Screenshot From 2025-06-18 22-18-18](https://github.com/user-attachments/assets/c1026308-2171-4b01-ab9c-24a9fd82d6fe)

* **Two subnets were created and attached to the VPC:**
    * One **public subnet** with CIDR `10.0.1.0/24` (256 IP addresses).
    * One **private subnet** with CIDR `10.0.2.0/24` (256 IP addresses).

![Screenshot From 2025-06-18 22-27-49](https://github.com/user-attachments/assets/3e24d139-be2b-4db6-b0e5-eb3ed3930560)

* An Internet Gateway named `my-personal-vpc-igw` was created and attached to `my-personal-vpc`.

![Screenshot From 2025-06-18 22-32-41](https://github.com/user-attachments/assets/066b5d3b-a546-483b-9eaa-8314e52766bc)

* A **Routing Table** was created and associated with the public subnet. A rule was configured to route internet-bound traffic (`0.0.0.0/0`) to the Internet Gateway.

![Screenshot From 2025-06-18 22-35-07](https://github.com/user-attachments/assets/136bcd2e-1ed8-4cd8-83a5-26ebddb37261)


**Security Misconfigurations Introduced in VPC/Networking:**
* The public subnet was directly associated with an Internet Gateway, allowing public EC2 access without strict ingress controls.
* **Overly permissive Network ACLs and Security Groups** were configured to allow unrestricted inbound rules (e.g., SSH, HTTP, MySQL ports) from `0.0.0.0/0` (anywhere).
* All traffic to/from public subnet EC2s was allowed without IP filtering or granular monitoring, demonstrating a lack of segmentation and firewall enforcement.

![Screenshot From 2025-06-18 22-47-12](https://github.com/user-attachments/assets/44d7601c-6364-40c3-9bec-ec156f61180a)


---

### Step 2: Create a Vulnerable EC2 Instance

AWS EC2 (Amazon Elastic Compute Cloud) provides resizable virtual servers (instances) for running applications.

**EC2 Instance Components:**
* **Instance Type:** Defines hardware capacity (CPU, memory).
* **AMI (Amazon Machine Image):** Specifies the operating system and pre-installed software.
* **Storage (EBS):** Configures the type and size of attached block storage.
* **Security Groups:** Firewall rules for instance-level traffic control.
* **Key Pair:** Used for SSH access authentication.
* **User Data:** Scripts executed upon instance launch for automated setup.

**Creating a Vulnerable EC2 Instance (`my-test-server`):**
* An EC2 instance named `my-test-server` was launched in the public subnet of our custom VPC.
* **AMI:** Amazon Linux 2 AMI was selected.
* **Instance Type:** `t2.micro` (free-tier eligible) was chosen.
* **Key Pair:** A new key pair was generated for SSH access.
* **Network Settings:** Attached to `my-personal-vpc` and the public subnet, with public IP assignment enabled.
* **Security Group:** A new Security Group was created to allow:
    * SSH on port `22`
    * HTTP on port `80`
    * MySQL on port `3306`
* **User Data:** A user-data script was added to automatically install desired applications and services (e.g., a web server, potentially a database).
* The instance was then launched.

![Screenshot From 2025-06-18 23-12-45](https://github.com/user-attachments/assets/0fe1e632-e86a-444b-acd7-a1756341b046)

![Screenshot From 2025-06-18 23-13-22](https://github.com/user-attachments/assets/8b65412b-755e-4185-85fb-94cd9b155351)

![Screenshot From 2025-06-18 23-25-33](https://github.com/user-attachments/assets/02b4c803-71df-4b08-be86-4b0cdf2aca15)

**Security Misconfigurations Introduced in EC2:**
* **Weak/Default SSH Key Pairs:** (Simulated/Demonstrated by exposing them elsewhere)
* **Security Group with Unrestricted Access:** `0.0.0.0/0` access was allowed on ports `22`, `80`, and `3306`, exposing these services globally.
* **MySQL Server with Default Credentials:** (If deployed via user-data) The MySQL server was configured with default/weak credentials, making it vulnerable to brute-force or direct access.

---

### Step 3: Deploy a Misconfigured S3 Bucket

AWS S3 (Simple Storage Service) is a scalable, cloud-based object storage service for managing large amounts of data.

**S3 Characteristics:**
* Stores data as objects.
* Globally unique bucket names.
* Region-specific.
* Each object within a bucket is stored as a key-value pair.

**Creating a Vulnerable and Publicly Exposed Bucket (`vulnerable-bucket-demo`):**
* An S3 bucket named `vulnerable-bucket-demo` was created.
* **"Block public access" was explicitly turned OFF** to make the bucket publicly accessible.

![Screenshot From 2025-06-18 23-49-37](https://github.com/user-attachments/assets/00e326ba-fec4-40a1-b11d-026ac57f6539)

* A **Bucket Policy** was generated (or configured manually) to allow public read access (`s3:GetObject`) to all bucket content for everyone (`*`).
* **Dummy confidential files** (e.g., `secret-credentials.txt`, `Alexa-credential.txt`) were uploaded to this bucket for data exposure testing.

![Screenshot From 2025-06-18 23-53-05](https://github.com/user-attachments/assets/89e651e8-99cf-4f48-ac02-6238f6d3f0a0)

![Screenshot From 2025-06-18 23-55-50](https://github.com/user-attachments/assets/7424f844-82f2-4084-b079-0d0610c917f1)

**Security Misconfigurations Introduced in S3:**
* **Public Read/Write Access:** Configured S3 buckets with public read access (and potentially public write for advanced demos), demonstrating accidental data exposure.
* **Confidential File Upload:** Intentionally uploaded sensitive files (e.g., `secret-credentials.txt`, `Alexa-credential.txt`) for data exfiltration testing.

![Screenshot From 2025-06-19 00-04-10](https://github.com/user-attachments/assets/b6b6ccb1-53c5-4f56-9557-ceca602c4ed1)


---

### Step 4: Over-Privileged IAM User

AWS IAM (Identity and Access Management) helps securely control access to AWS resources by managing users, roles, and permissions.

**IAM Services Provided:**
* **Create Users:** Individual user accounts for accessing AWS resources.
* **Assign Permissions:** Control actions users can perform on AWS services.
* **Create Groups:** Group users and assign permissions collectively.
* **Create Roles:** Assign temporary permissions to AWS services or users.
* **Define Policies:** Create and attach custom policies for fine-grained permissions.

**Creating an Over-privileged IAM User (`temp-user`):**
* An IAM user named `temp-user` was created with a custom password.
* **Crucial Misconfiguration:** The `AdministratorAccess` policy was directly assigned to this user (by adding it to an Admin group or direct attachment). This makes `temp-user` an over-privileged IAM user.

![Screenshot From 2025-06-19 00-19-17](https://github.com/user-attachments/assets/f96f0f59-7b86-49a6-a77f-dcb070c365b9)

![Screenshot From 2025-06-19 00-19-44](https://github.com/user-attachments/assets/66eac96e-ae1e-4053-8d13-bd94edd5d049)


**Security Misconfigurations Introduced in IAM:**
* **Attached `AdministratorAccess` to a Normal User:** Violation of the Principle of Least Privilege, granting excessive permissions.
* **Credential Exposure:** The Access Key ID and Secret Access Key for `temp-user` are intentionally placed in vulnerable locations within the lab environment (e.g., a publicly accessible file on the `web-server-ec2`, or hardcoded within the Lambda function's source code/environment variables) for discovery.

---

### Step 5: Set up CloudTrail with Weak Configuration

AWS CloudTrail is a service that records API calls made on your AWS account, delivering log files to an S3 bucket for auditing, security monitoring, and operational troubleshooting.

**CloudTrail Features:**
* API Call Logging, Security Auditing, and Compliance Monitoring.
* Allows users and administrators to manage logs and track activities.
* Facilitates activity tracking and investigation of resource changes.

![Screenshot From 2025-06-19 22-43-34](https://github.com/user-attachments/assets/2644ee23-f089-4c0f-9310-4975ea5a7e04)


**Security Misconfigurations Introduced in CloudTrail:**
* **Log File Integrity Validation Disabled:** This crucial security feature was intentionally disabled, allowing an attacker to modify or delete log files within the destination S3 bucket without AWS being able to detect the tampering.
* **Logging to a Compromisable S3 Bucket:** The CloudTrail logs are delivered to `vulnerable-bucket-for-trail` (which is publicly writeable or deletable by a compromised user like `OverPrivilegedAdmin` or an EC2 role with `s3:DeleteObject` permissions on this bucket).
* **Missing Management Events (if applicable):** Could be configured to log only "Read" events and not "Write" events, making it harder to detect configuration changes made by an attacker.
* **Lack of Multi-Region Trail:** The trail was configured for only `ap-south-1` region, allowing an attacker to perform actions in other regions (e.g., `eu-central-1`, `us-east-1`) without being logged.

---

### Step 6: Setup Lambda Function with Hardcoded Secrets

AWS Lambda is a serverless computing service that executes code in response to events without requiring server management.

**Lambda Creation Steps:**
1.  **Navigate to Lambda service:** Start by creating a new Lambda function.
2.  **Choose Runtime Environment:** Select a runtime (e.g., Python 3.9).
3.  **Choose Architecture Type:** Select the desired architecture.
4.  **Create IAM Role for Execution:** A new IAM role was created for the Lambda function's execution permissions.
5.  **Function Creation:** The function was then created.

![Screenshot From 2025-06-19 20-06-00](https://github.com/user-attachments/assets/b7f06764-4ee2-440a-acee-9c3c30fb5ec8)

6.  **Code Editor/ZIP File:** A sample Lambda function was created using the in-built code editor or by uploading a ZIP file.
7.  **Event Trigger:** A demo event was created to trigger and execute the Lambda function.

![Screenshot From 2025-06-19 22-27-17](https://github.com/user-attachments/assets/6ffd6bff-fd18-4b82-ac80-b6605c34dc90)

![Screenshot From 2025-06-19 22-39-12](https://github.com/user-attachments/assets/2b110886-c07e-4720-9460-2b3e1a20991f)


**Security Misconfigurations Introduced in Lambda:**
* **Hardcoded Credentials:** The Python code of the Lambda function (e.g., `SecretDisclosureFunc`) directly contains the Access Key ID and Secret Access Key of the `OverPrivilegedAdmin` IAM user. These credentials are embedded within the deployable ZIP file for the function.
* **Overly Permissive Execution Role:** The Lambda function's IAM execution role (e.g., `arn:aws:iam::ACCOUNT_ID:role/lambda-basic-execution-role`) has broader permissions than required for its intended function. This creates an elevated risk if an attacker compromises the function's execution.
* **No KMS Encryption for Environment Variables:** If sensitive credentials were stored in environment variables, they were left unencrypted, making them easily retrievable if an attacker can read the function's configuration.

