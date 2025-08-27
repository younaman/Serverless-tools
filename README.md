# Risky Permission Chaining Attack Detection Tool

This repository contains two scanning tools designed for auditing privilege escalation risks in cloud environments:

- **`aws_escalate.py`**: A scanning tool for Amazon Web Services (AWS) accounts.
- **`aliyun_escalate.py`**: A scanning tool for Alibaba Cloud (Aliyun) accounts.
## Exact Environment Versions and Files
In addition to the main scripts, the repository includes the following files and directories:

- **`requirements.txt`**: A list of Python libraries, including specific version requirements, needed for running `aliyun_escalate.py`. Note that the execution of aws_escalate.py can be directly maked in the AWS Cloud CLI, and it doesn't need any specific versions or requirements.
- **`fc2/`**: A Python library folder used by `aliyun_escalate.py`.
- **Example Output Files**: 
  - `aws_output.txt`: Example output for `aws_escalate.py`.  
  - `aliyun_output.txt`: Example output for `aliyun_escalate.py`.
- **`README.md`**: This file, providing an overview of the repository.
- **`LICENSE`**: The license file specifying the terms under which this software can be used, modified, and distributed.
> **Note**: These tools are in the early stages of development and serve as a proof-of-concept (PoC).

---

## **Features**
- Enumerate all roles and their attached policies.  
- Enumerate all Function Compute (FC) services/Lambda applications and functions, and map their effective roles.  
- Analyze and output confirmed privilege escalation paths.  
- Simulate cross-account contamination scenarios and output detailed attack paths.  
- Output function-based attack paths and sensitive permission locations.

---

## Dependencies and Requirements

### Hardware Dependencies

Our artifact experiments are conducted on serverless platforms provided by AWS and Alibaba Cloud. Accessing these cloud environments requires only standard laptops or desktops.

### Software Dependencies

- **Scanner for Amazon Web Services**:
  The scanning tool for AWS operates directly within the **AWS CloudShell** environment, an integrated terminal provided by the AWS cloud platform. To use this tool, you will need:
  - AWS account credentials.
  - Access keys for AWS users or roles to authenticate and perform the required operations.

- **Scanner for Alibaba Cloud**:
  The scanning tool for the Aliyun serverless platform is executed locally in a Python environment. The requirements include:
  - Python version 3.10 or higher.
  - The `fc2` library and other dependencies specified in the `requirements.txt` file.
  - Access keys for Aliyun users or roles for authentication.

---

## **AWS Scanning Tool (`aws_escalate.py`)**

### **Description**
This script (aws_escalate.py) is designed to enumerate all IAM roles and Lambda functions in your AWS account, analyze their permissions, and detect possible privilege escalation paths, including cross-account contamination scenarios.

### **Setup and Usage**

1. **Log In and Upload Files**

Log in to the Amazon Web Services (AWS) cloud platform, and upload `aws_escalate.py` file to the `/home/cloudshell-user` directory in CloudShell. If you do not have an AWS account, please register an account.

2. **Modify the Credentials File**

Update the `credentials` file located in the `/home/cloudshell-user/.aws` directory with the following format:
```plaintext
   [default]
   aws_access_key_id = AKIA*****   # AccessKeyID
   aws_secret_access_key = ******* # SecretAccessKey
```
The role or user associated with these access keys must have permission to access all resources within the account.

3. (Optional) **Install Serverless Applications**

Open the Lambda page on the AWS platform, click “Applications” in the right sidebar, then click “Create application” on the left. On the page that opens, select “Serverless application” and choose an application template to create your serverless application. Taking measure-cold-start as an example, direct deployment from the AWS Serverless Application Repository may result in a runtime mismatch error, indicating incompatibility with the current AWS platform. The solution involves modifying the 'runtime' parameter in the application template to specify a supported runtime version, after which the application can be successfully redeployed. 

4. **Run the Tool**

Execute the script on cloudshell using the following command:
```plaintext
python ./aws_escalate.py -p default > aws_output.txt
```
If you do not specify a profile [-p default], you will be prompted to select one from your AWS CLI configuration.

The output of the scan will be saved to `aws_output.txt`.

5. **Download and Review Results**

After the script completes, download the `aws_output.txt` file to view the scanning results.

### **Example Output**

```plaintext
Application: my-stack
  Function: my-lambda-func
    Role ARN: arn:aws:iam::123456789012:role/my-role
    CONFIRMED: ['iam:PassRole', 'lambda:CreateFunction']
  ----------------------------------------
============================================================

...

Scan the attack paths in the account.

The privilege escalation paths in the account:
    confirm: 'iam:PassRole+lambda:CreateFunction' -> 'iam:CreateRole+iam:AttachRolePolicy' -> function_escalation_method2

Here are function-based attack paths in the account.

    confirm: {iam:PassRole}my-stack:my-lambda-func+{lambda:CreateFunction}my-stack:my-lambda-func -> '{iam:CreateRole}my-stack:my-lambda-func+{iam:AttachRolePolicy}my-stack:my-lambda-func' -> function_escalation_method2

...

Account-Level and Inter-Account Attack Path Analysis
============================================================

Simulate two accounts, both of which have been provisioned with all the aforementioned applications, and detect three attack paths.

Account 1:
  The account contains the following applications:
    my-stack, another-stack
  Confirmed escalated permission: 
    ['iam:PassRole', 'lambda:CreateFunction', ...]

  The privilege escalation paths in Account 1:
    confirm: 'iam:PassRole+lambda:CreateFunction' -> 'iam:CreateRole+iam:AttachRolePolicy' -> function_escalation_method2

  Here are function-based attack paths in Account 1.

    confirm: {iam:PassRole}my-stack:my-lambda-func+{lambda:CreateFunction}my-stack:my-lambda-func -> '{iam:CreateRole}my-stack:my-lambda-func+{iam:AttachRolePolicy}my-stack:my-lambda-func' -> function_escalation_method2

...

===Check cross-account attack paths (Attack Path 3)===

1. LAYER-BASED CONTAMINATION:
   Due to Attack Path 1 or 2 in Account 1, Account 1 can infect Account 2 through Lambda Layer manipulation.
   Required permission: lambda:UpdateFunctionConfiguration
   Functions with Sensitive Permissions:

     Permission: lambda:UpdateFunctionConfiguration
     - my-stack:my-lambda-func (Role: arn:aws:iam::123456789012:role/my-role)
```

### **Test Cases**

- Minimal Permissions (No Escalation)
 **Setup**: Create a role with read-only permissions and associate this role with a Lambda function in the account.
 **Expected Output**:  
  - The function should be marked as "it is safe!"  
  - No privilege escalation paths should be found.  

- Confirmed Escalation Path
  **Setup**: Create a role with escalation-related permissions (e.g., `sts:AssumeRole` and `lambda:UpdateFunctionCode`), and assign it to a Lambda function.  
  **Expected Output**:  
  - The function should list these permissions as CONFIRMED.  
  - The script should output privilege escalation paths (Attack path 1 or 2) involving these permissions.  

- Cross-Account Contamination
  **Setup**: Multiple stacks/functions, at least one of which in Account 2 has the `lambda:UpdateFunctionConfiguration` permission, and attack strategies 1 or 2 can be implemented in Account 1 (for example, the functions in Account 1 have `sts: AssumeRole` or `lambda: UpdateFunctionCode`).
  **Expected Output**:  
  - The script should output the "LAYER-BASED CONTAMINATION" section under cross-account attack paths (Attack path 3).  

- Performance Testing with Multiple Applications
  **Setup**: Install 200 serverless applications in the account. Then run the scanning tool to assess its performance and functionality under this scale.
  **Expected Output**:
  - The tool should successfully enumerate all applications and their associated permissions.
  - The script should accurately identify and output any privilege escalation paths present.
  - The tool is expected to take several minutes to complete.

---

## **Aliyun Scanning Tool (aliyun_escalate.py)**

### **Description**
This script (aliyun_escalate.py) enumerates all RAM roles and Function Compute (FC) functions in your Alibaba Cloud account, analyzes their permissions, and detects possible privilege escalation paths, including cross-account contamination scenarios.

### **Setup and Usage**

1. **Install Required Python Libraries**

Use the following command to install the required Python libraries:

```plaintext
pip install -r requirements.txt  
```

Then copy the folder "fc2" to the corresponding location of the reference function library.
Ensure you have installed all necessary Python libraries for running the script.

2. (Optional) **Register Aliyun Account and Log In**

If you do not have an Alibaba Cloud account, please register an account and log in to obtain your access key.

3. (Optional) **Install Function Compute Applications**

Open the Function Compute page on the Aliyun platform, click “Applications” in the right sidebar, then click “Create Application” on the left. On the page that opens, click 'Create Application from Template' and select an application template to create your serverless application. For instance, to deploy the fc-stable-diffusion application, first locate it in the Alibaba Serverless Application Center, click to access its deployment page, configure the required parameters, and proceed with deployment.

4. **Create the Input File**

Create `aliyun_input.txt` file with the appropriate values corresponding to your environment, and place this file in the same directory as 'aliyun_escalate.py'.
The content format of aliyun_input.txt is as follows:

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
The role or user associated with these access keys must have permission to access all resources within the account.

5. **Run the Tool**

Execute the script using the following command:

```plaintext
python ./aliyun_escalate.py < aliyun_input.txt > aliyun_output.txt
```
The output of the scan will be saved to aliyun_output.txt.

6. **Review Results**

After the script completes, open the `aliyun_output.txt` file to review the scan results.

---

### **Example Output**

```plaintext
Access Key ID: 
Secret Access Key: 
Region ID:
Account ID:

Creating FC Client with endpoint: <your_account_id>.<region_id>.fc.aliyuncs.com
FC Client created successfully.
Listing services and their functions...

Service: my-fc-service
  Function: my-func-1
    Role ARN: acs:ram::1234567890123456:role/my-role
    CONFIRMED: ['ram:PassRole', 'fc:CreateFunction']
  Function: my-func-2
    Role ARN: acs:ram::1234567890123456:role/another-role
    It is safe!
============================================================

...

Scan the attack paths in the account.

The privilege escalation paths in the account:
    confirm: 'ram:PassRole+fc:CreateFunction' -> 'ram:CreateRole+ram:AttachRolePolicy' -> function_escalation_method2

Here are function-based attack paths in the account.

    confirm: {ram:PassRole}my-fc-service:my-func-1+{fc:CreateFunction}my-fc-service:my-func-1 -> '{ram:CreateRole}my-fc-service:my-func-1+{ram:AttachRolePolicy}my-fc-service:my-func-1' -> function_escalation_method2

...

Account-Level and Inter-Account Attack Path Analysis
============================================================

Simulate two accounts, both of which have been provisioned with all the aforementioned services, and detect three attack paths.

Account 1:
  The account contains the following services:
    my-fc-service, another-service
  Confirmed escalated permission: 
    ['ram:PassRole', 'fc:CreateFunction', ...]

  The privilege escalation paths in Account 1:
    confirm: 'ram:PassRole+fc:CreateFunction' -> 'ram:CreateRole+ram:AttachRolePolicy' -> function_escalation_method2

  Here are function-based attack paths in Account 1.

    confirm: {ram:PassRole}my-fc-service:my-func-1+{fc:CreateFunction}my-fc-service:my-func-1 -> '{ram:CreateRole}my-fc-service:my-func-1+{ram:AttachRolePolicy}my-fc-service:my-func-1' -> function_escalation_method2

...

===There are cross-account attack paths (Attack Path 3)===

1. LAYER-BASED CONTAMINATION:
   Due to Attack Path 1 or 2 in Account 1, Account 1 can infect Account 2 through FC Layer manipulation.
   Required permission: fc:UpdateFunctionConfiguration
   Functions with Sensitive Permissions:

     Permission: fc:UpdateFunctionConfiguration
     - my-fc-service:my-func-1 (Role: acs:ram::1234567890123456:role/my-role)
```

### **Test Cases**

- Minimal Permissions (No Escalation)
 **Setup**: Create a role with read-only permissions and associate this role with a function in the account.
 **Expected Output**:  
  - The function should be marked as "it is safe!"  
  - No privilege escalation paths should be found.  

- Confirmed Escalation Path
  **Setup**: Create a role with escalation-related permissions (e.g., `sts:AssumeRole` and `fc:UpdateFunctionCode`), and assign it to a function.  
  **Expected Output**:  
  - The function should list these permissions as CONFIRMED.  
  - The script should output privilege escalation paths (Attack path 1 or 2) involving these permissions.  

- Cross-Account Contamination
  **Setup**: Multiple stacks/functions, at least one of which in Account 2 has the `fc:UpdateFunctionConfiguration` permission, and attack strategies 1 or 2 can be implemented in Account 1 (for example, the functions in Account 1 have `sts: Assumerole` or `fc: UpdateFunctionCode`).
  **Expected Output**:  
  - The script should output the "LAYER-BASED CONTAMINATION" section under cross-account attack paths(Attack path 3).  

- Invalid/Expired Credentials
  **Setup**: Run the script with invalid or expired AWS credentials.  
  **Expected Output**:  
  - The script should fail gracefully and print an error message.
  
---

## **Current Development Status**
These tools are currently in the "strawman design" phase, and we are actively working toward achieving the following goals:

1. **Automatic Identification of High-Risk Third-Party Applications**
Enhance the tools to automatically identify all third-party applications within the account that pose potential risks.

2. **Construction of Attack Paths**
Construction of Attack Paths
Leverage dangerous functions of third-party applications to construct actionable attack paths.

3. **Automated PoC Generation**
Build a comprehensive tool capable of analyzing all third-party applications and automatically generating Proof-of-Concept (PoC) exploits to simulate potential attacks.

In addition, we used these two tools to scan the sensitive applications of Lambda on Amazon Web Services and Function Compute on Alibaba Cloud respectively. The output results are in `aliyun_output.txt` and `aws_output.txt` under the `output` folder.

## **Disclaimer**
- This script is for security research and auditing purposes only. Do not use on accounts you do not own or have explicit permission to test.  
- For large accounts, the script may take several minutes to complete enumeration.
  
## **Feedback and Contributions**
We welcome feedback, suggestions, and contributions to improve these tools. If you encounter any issues or have ideas for enhancement, feel free to open an issue or submit a pull request. Thank you for your interest!

## License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
