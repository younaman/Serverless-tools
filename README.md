# Cloud Privilege Escalation Path Scanner

This repository contains two scanning tools designed for auditing privilege escalation risks in cloud environments:

- **`aws_escalate.py`**: A scanning tool for AWS accounts.
- **`aliyun_escalate.py`**: A scanning tool for Aliyun accounts.

These tools are in the early stages of development and serve as a proof-of-concept (PoC). 

## **Features**
- Enumerate all roles and their attached policies.  
- Enumerate all Function Compute (FC/Lambda) services and functions, and map their effective roles.  
- Analyze and output confirmed privilege escalation paths.  
- Simulate cross-account contamination scenarios and output detailed attack paths.  
- Output function-based attack paths and sensitive permission locations.

Below are the detailed instructions for using each tool.

---

## **AWS Scanning Tool (`aws_escalate.py`)**

### **Description**
This script (aws_escalate16.py) is designed to enumerate all IAM roles and Lambda functions in your AWS account, analyze their permissions, and detect possible privilege escalation paths, including cross-account contamination scenarios.

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
If you do not specify a profile [-p default], you will be prompted to select one from your AWS CLI configuration.

The output of the scan will be saved to `aws_output.txt`.

3. **Download and Review Results**
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
 **Setup**: Create a role with only read-only permissions, and a Lambda function using this role.  
 **Expected Output**:  
  - The function should be marked as "it is safe!"  
  - No privilege escalation paths should be found.  

- Confirmed Escalation Path
  **Setup**: Create a role with escalation-related permissions (e.g., `iam:PassRole` and `lambda:CreateFunction`), and assign it to a Lambda function.  
  **Expected Output**:  
  - The function should list these permissions as CONFIRMED.  
  - The script should output a privilege escalation path involving these permissions.  

- Cross-Account Contamination
  **Setup**: Multiple stacks/functions, at least one with `lambda:UpdateFunctionConfiguration` permission.  
  **Expected Output**:  
  - The script should output the "LAYER-BASED CONTAMINATION" section under cross-account attack paths.  

- Deny Policies
  **Setup**: A role with `*` allow but explicit deny on escalation actions.  
  **Expected Output**:  
  - The script should indicate "Might already be an admin, check any explicit denies or policy condition keys!"  
  - No confirmed escalation path.  

- Invalid/Expired Credentials
  **Setup**: Run the script with invalid or expired AWS credentials.  
  **Expected Output**:  
  - The script should fail gracefully and print an error message.  

---

## **Aliyun Scanning Tool (aliyun_escalate.py)**

### **Description**
This script (aliyun_escalate6.py) enumerates all RAM roles and Function Compute (FC) functions in your Alibaba Cloud account, analyzes their permissions, and detects possible privilege escalation paths, including cross-account contamination scenarios.

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
  **Setup**: Create a RAM role with only read-only permissions, and a FC function using this role.  
  **Expected Output**:  
  - The function should be marked as "It is safe!"  
  - No privilege escalation paths should be found.  

- Confirmed Escalation Path
  **Setup**: Create a RAM role with `ram:PassRole` and `fc:CreateFunction` permissions, and assign it to a FC function.  
  **Expected Output**:  
  - The function should list these permissions as CONFIRMED.  
  - The script should output a privilege escalation path involving these permissions.  

- Cross-Account Contamination
  **Setup**: Multiple services/functions, at least one with `fc:UpdateFunctionConfiguration` permission.  
  **Expected Output**:  
  - The script should output the "LAYER-BASED CONTAMINATION" section under cross-account attack paths.  

- Deny Policies
  **Setup**: A role with `*` allow but explicit deny on escalation actions.  
  **Expected Output**:  
  - The script should indicate "Might already be an admin, check any explicit denies or policy condition keys!"  
  - No confirmed escalation path.  

- Invalid/Expired Credentials
  **Setup**: Run the script with invalid or expired Access Key/Secret.  
- **Expected Output**:  
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

## **Disclaimer**
- This script is for security research and auditing purposes only. Do not use on accounts you do not own or have explicit permission to test.  
- For large accounts, the script may take several minutes to complete enumeration.
  
## **Feedback and Contributions**
We welcome feedback, suggestions, and contributions to improve these tools. If you encounter any issues or have ideas for enhancement, feel free to open an issue or submit a pull request. Thank you for your interest!
