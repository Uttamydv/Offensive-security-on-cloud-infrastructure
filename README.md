# Offensive-security-on-cloud-infrastructure
This is my Btech final year project where I explore various Offensive Security techniques on dummy enterprise infrastructure on AWS 

## Project Overview

This repository contains the resources and documentation for a major academic project focused on demonstrating offensive security techniques against intentionally vulnerable cloud infrastructure. The project aims to provide practical insights into common cloud misconfigurations and attack vectors within the Amazon Web Services (AWS) environment, simulating real-world penetration testing scenarios from an attacker's perspective.

The core objective is to showcase how seemingly minor cloud security oversights can be exploited, emphasizing the critical importance of secure cloud architecture, robust configurations, and continuous security assessments.
Features & Implemented Vulnerabilities

This project sets up and exploits the following intentionally vulnerable components within AWS:

    VPC & Subnets: A multi-tiered network architecture with public and private subnets, mimicking typical enterprise cloud deployments.
    Vulnerable EC2 Instance:
        Misconfigured Security Group: SSH (Port 22) open to the internet.
        Web Application with SSRF: An application that can be coerced into making requests to the EC2 Instance Metadata Service (IMDSv1), leading to IAM Role Credential Disclosure.
        Weak/Default Credentials: (Simulated/Demonstrated)
    Misconfigured S3 Bucket:
        Public Read/Write Access: Configured to allow public access to objects, enabling data exfiltration and potential injection/defacement.
        Contains Sensitive Information: Intentionally seeded with mock credentials, configuration files, and other sensitive data.
    Over-privileged IAM User:
        An IAM User assigned AdministratorAccess policy, demonstrating the critical impact of violating the Principle of Least Privilege.
        Credentials intentionally exposed within the lab environment for discovery.
    Misconfigured CloudTrail:
        Logging to Compromised S3 Bucket: Logs directed to the publicly accessible S3 bucket.
        Log File Integrity Validation Disabled: Allows an attacker to delete or modify logs undetected.
        Non-multi-region Trail: (If applicable) Demonstrates blind spots in logging.
    Lambda Function with Secret Disclosure:
        A serverless function containing hardcoded AWS credentials (for the over-privileged IAM user) within its code or unencrypted environment variables.

### Project Structure

The repository is organized as follows:

    ./terraform/: Contains all Infrastructure as Code (IaC) files (e.g., .tf files) for provisioning the entire vulnerable AWS lab environment.
    ./attack-scripts/: Custom scripts and commands used to perform offensive operations and exploit vulnerabilities.
    ./setup-lab-environmeent/:contains the steps and procedure to setup the misconfigured cloud environment.
    ./documentation/: Project report, system design, architecture diagrams, and other detailed documentation.
    ./screenshots/: Visual evidence of successful exploits and vulnerabilities.
    ./lambda-payload/: Source code and deployment package for the vulnerable Lambda function.

###Prerequisites

To set up and interact with this project, you will need:

    AWS Account: A dedicated, non-production AWS account (e.g., Free Tier or student account) where you have full administrative access to create and manage resources.
        WARNING: Ensure you operate strictly within this dedicated account. Do NOT use production or critical accounts.
    AWS CLI: Configured with credentials for your dedicated AWS account.
    Terraform: Installed (v1.0+ recommended) for provisioning the infrastructure.
    Python 3.x: Installed for custom attack scripts and Lambda function development.
    Git: For cloning the repository.
    Offensive Security Toolkit: A Linux distribution like Kali Linux or an equivalent environment with tools such as:
        nmap
        curl
        aws-cli (already listed)
        Pacu (AWS exploitation framework)
        Prowler (for initial reconnaissance/auditing from an attacker's perspective)
        ssh client

### Setup the lab Environment

This Archeitecure of the cloud environment is as follow:
img

### Offensive Operations & Exploitation

Once the environment is deployed, you can begin the offensive operations. Refer to the detailed steps and scripts in the ./documentation/ and ./attack-scripts/ directories for precise instructions.

A general attack flow involves:

    Reconnaissance: Identifying public-facing assets (EC2 IP, S3 bucket URL).
    Initial Access: Exploiting web-server-ec2 via SSH or SSRF.
    Credential Discovery & Privilege Escalation: Extracting IAM credentials from EC2 metadata, S3 bucket, or Lambda function. Using tools like Pacu to escalate privileges with compromised credentials.
    Lateral Movement & Persistence: Enumerating additional resources, manipulating CloudTrail logs, creating new persistence mechanisms.
    Data Exfiltration: Retrieving sensitive data from compromised services.

Teardown (Crucial!)

It is absolutely critical to tear down all provisioned resources after you have completed your project to avoid incurring unexpected AWS costs. After completing your all the enummeration and attack, destroy all the aws resources like EC2-instances, S3
bucket, AMIs, IAM users, lambda-function etc because after our work is done, they just cause the unnecessary cost.


Project Documentation & Report

The full project report, including detailed methodology, system design, attack demonstrations, findings, and recommendations, is available in the ./documentation/ directory.
Ethical Considerations & Disclaimer

This project is developed for educational and academic purposes only.

    NEVER use these techniques or tools against any system or cloud environment for which you do not have explicit written permission.
    All activities must be confined to the isolated lab environment explicitly created for this project.
    The authors and contributors are not responsible for any misuse or illegal activities conducted using the information or code provided in this repository.
    Always adhere to the highest ethical standards and legal regulations when engaging in any form of security testing.
