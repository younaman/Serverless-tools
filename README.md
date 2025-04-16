About the Scanning Tools
This repository contains two scanning tools designed for analyzing applications in cloud environments: aws_escalate.py for AWS accounts and aliyun_escalate.py for Aliyun accounts. Below are the detailed instructions for using these tools.

1. AWS Scanning Tool (aws_escalate.py)
Description
The aws_escalate.py script is designed to scan applications within an AWS account. It requires uploading the script to AWS CloudShell and modifying the credentials file before execution.

Setup and Usage
Upload the Script
Upload the aws_escalate.py script to your AWS CloudShell environment.
Modify the Credentials File
Update the credentials file located in the .aws directory with the following format:

[default]
aws_access_key_id = AKIA*****   # AccessKeyID
aws_secret_access_key = ******* # SecretAccessKey

Ensure that the role or user associated with these access keys has permission to access all resources within the account.
Run the Tool
Execute the script using the following command:

python ./aws_escalate.py -p default > aws_output.txt
The output of the scan will be saved to aws_output.txt.
Download and Review Results
After the script completes, download the aws_output.txt file to view the scanning results.
2. Aliyun Scanning Tool (aliyun_escalate.py)
Description
The aliyun_escalate.py script is designed to scan applications within an Aliyun account. It requires the installation of specific Python libraries and a properly configured input file.

Setup and Usage
Install Required Python Libraries
Ensure you have installed the necessary Python libraries for running the script.
Modify the Input File
Update the aliyun_input.txt file with the appropriate values corresponding to your environment.
Run the Tool
Execute the script using the following command:

python ./aliyun_escalate.py < aliyun_input.txt > aliyun_output.txt
The output of the scan will be saved to aliyun_output.txt.
Review Results
After the script completes, open the aliyun_output.txt file to review the scan results.
Current Status
Please note that both tools are still in a preliminary "strawman" design phase, and we are actively working toward achieving the following goals:

Automatic Identification of High-Risk Third-Party Applications
The tools will be enhanced to automatically identify all third-party applications within the account that pose potential risks.
Construction of Attack Paths
The tools will leverage dangerous functions of third-party applications to construct actionable attack paths.
Automated PoC Generation
Our ultimate goal is to build a comprehensive tool capable of analyzing all third-party applications and automatically generating Proof-of-Concept (PoC) exploits to simulate potential attacks.
We appreciate your interest and welcome any feedback or suggestions as we continue to refine and improve these tools!
