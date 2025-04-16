# Cloud Application Scanning Tools

This repository contains two scanning tools designed for analyzing applications in cloud environments:

- **`aws_escalate.py`**: A scanning tool for AWS accounts.
- **`aliyun_escalate.py`**: A scanning tool for Aliyun accounts.

These tools are in the early stages of development and serve as a proof-of-concept (PoC). Below are the detailed instructions for using each tool.

---

## **AWS Scanning Tool (`aws_escalate.py`)**

### **Description**
The `aws_escalate.py` script scans applications within an AWS account to identify potential risks. It requires uploading to **AWS CloudShell** and modifying the credentials file before execution.

### **Setup and Usage**

1. **Upload the Script**  
   Upload the `aws_escalate.py` script to your AWS CloudShell environment.

2. **Modify the Credentials File**  
   Update the `credentials` file located in the `.aws` directory with the following format:
   ```plaintext
   [default]
   aws_access_key_id = AKIA*****   # AccessKeyID
   aws_secret_access_key = ******* # SecretAccessKey analyzing all third-party applications and automatically generating Proof-of-Concept (PoC) exploits to simulate potential attacks.
We appreciate your interest and welcome any feedback or suggestions as we continue to refine and improve these tools!
