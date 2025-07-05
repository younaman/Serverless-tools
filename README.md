# Cloud Privilege Escalation Path Scanner

This repository contains two scanning tools designed for auditing privilege escalation risks in cloud environments:

- **`aws_escalate.py`**: A scanning tool for AWS accounts.
- **`aliyun_escalate.py`**: A scanning tool for Aliyun accounts.

These tools are in the early stages of development and serve as a proof-of-concept (PoC). Below are the detailed instructions for using each tool.

## **Features**
- Enumerate all roles and their attached policies.  
- Enumerate all Function Compute (FC/Lambda) services and functions, and map their effective roles.  
- Analyze and output confirmed and potential privilege escalation paths.  
- Simulate cross-account contamination scenarios and output detailed attack paths.  
- Output function-based attack paths and sensitive permission locations.

---

## **AWS Scanning Tool (`aws_escalate.py`)**

### **Description**
The `aws_escalate.py` script scans applications within an AWS account to identify potential risks. It requires uploading to **AWS CloudShell** and modifying the credentials file before execution.

### **Setup and Usage**

1. **Modify the Credentials File**
   Update the `credentials` file located in the `.aws` directory with the following format in AWS CloudShell:
```plaintext
   [default]
   aws_access_key_id = AKIA*****   # AccessKeyID
   aws_secret_access_key = ******* # SecretAccessKey
```
The role or user associated with these access keys must have permission to access all resources within the account.

2. **Run the Tool**
  Execute the script using the following command:

```plaintext
python ./aws_escalate.py -p default > aws_output.txt
```

The output of the scan will be saved to `aws_output.txt`.

3. **Download and Review Results**
After the script completes, download the `aws_output.txt` file to view the scanning results.

## **Aliyun Scanning Tool (aliyun_escalate.py)**

### **Description**
The `aliyun_escalate.py` script scans applications within an Aliyun account to identify potential risks. It requires the installation of specific Python libraries and a properly configured input file.

### **Setup and Usage**

1. **Install Required Python Libraries**
Install Required Python Libraries

```plaintext
pip install -r requirements.txt  
```

Then copy the folder "fc2" to the corresponding location of the reference function library.
Ensure you have installed all necessary Python libraries for running the script.

2. **Create the Input File**
Create `aliyun_input.txt` file with the appropriate values corresponding to your environment.The content format of aliyun_input.txt is as follows:

```plaintext
<Access Key ID>
<Secret Access Key>
<Region ID>
<Account ID> 
```

For example：

```plaintext
LTAI5t...
abc1234567890abcdef
cn-hangzhou  
1234567890123456  
```

And place this file in the same directory as 'aliyun_escalate.py'.
3. **Run the Tool**
Execute the script using the following command:

```plaintext
python ./aliyun_escalate.py < aliyun_input.txt > aliyun_output.txt
```
The output of the scan will be saved to aliyun_output.txt.

4. **Review Results**
After the script completes, open the `aliyun_output.txt` file to review the scan results.

## **Current Development Status**
These tools are currently in the "strawman design" phase, and we are actively working toward achieving the following goals:

1. **Automatic Identification of High-Risk Third-Party Applications**
Enhance the tools to automatically identify all third-party applications within the account that pose potential risks.

2. **Construction of Attack Paths**
Construction of Attack Paths
Leverage dangerous functions of third-party applications to construct actionable attack paths.

3. **Automated PoC Generation**

Build a comprehensive tool capable of analyzing all third-party applications and automatically generating Proof-of-Concept (PoC) exploits to simulate potential attacks.

## **Disclaimer**
These tools are intended for research and educational purposes only. Use them responsibly and only with proper authorization. Unauthorized use of these tools may violate applicable laws and regulations.

## **Feedback and Contributions**
We welcome feedback, suggestions, and contributions to improve these tools. If you encounter any issues or have ideas for enhancement, feel free to open an issue or submit a pull request. Thank you for your interest!
