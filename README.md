这是我们论文的扫描工具。对于第三方应用程序，首先，您需要安装它。之后，您可以运行此工具，它将识别此第三方应用程序的关键组件和关键守护进程集。请注意，它仍然是一个稻草人设计，我们仍在努力实现以下目标：1. 自动识别所有具有潜在风险的第三方应用程序。2. 利用第三方应用程序的关键组件自动发起攻击。我们的目标是构建一个工具来分析所有第三方应用程序并生成 PoC 以自动发起过度权限攻击。
这是我们论文的两个扫描工具。
aws_escalate.py是针对AWS账户上应用程序的扫描工具，首先，您需要将它上传到CloudShell，在运行前，需要把.aws文件夹下的credentials的内容修改如下：
[default]
aws_access_key_id = AKIA*****   #AccessKeyID
aws_secret_access_key = *******   #SecretAccessKey
此处的访问密钥所属的角色或用户必须具有访问账户内所有资源的权限。
使用python ./aws_escalate.py -p default > output.txt命令运行该扫描工具，然后下载output.txt后就能查看扫描结果。
aliyun_escalate.py是针对Aliyun账户上应用程序的扫描工具，首先，您需要下载配套的python函数库
