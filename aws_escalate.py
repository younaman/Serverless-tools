#!/usr/bin/env python3
import boto3
import argparse
import sys
import re
from itertools import combinations,product
from botocore.exceptions import ClientError, ProfileNotFound

def main(args):
    #Upload the AWS CLI file
    if args.profile is None:
        session = boto3.Session()
        print('No AWS CLI profile passed in, choose one below or rerun the script using the -p/--profile argument:')
        profiles = session.available_profiles
        for i in range(0, len(profiles)):
            print('[{}] {}'.format(i, profiles[i]))
        profile_number = int(input('Choose a profile (Ctrl+C to exit): ').strip())
        profile_name = profiles[profile_number]
        session = boto3.Session(profile_name=profile_name)
    else:
        try:
            profile_name = args.profile
            session = boto3.Session(profile_name=profile_name)
        except ProfileNotFound as error:
            print('Did not find the specified AWS CLI profile: {}\n'.format(args.profile))

            session = boto3.Session()
            print('Profiles that are available: {}\n'.format(session.available_profiles))
            print('Quitting...\n')
            sys.exit(1)

    roles = []
    client = session.client('iam')

    # List roles
    response = client.list_roles()
    for role in response['Roles']:
        roles.append({'RoleName': role['RoleName'], 'Permissions': {'Allow': {}, 'Deny': {}}})
    while response.get('IsTruncated'):
        response = client.list_roles(
            Marker=response['Marker']
        )
        for role in response['Roles']:
            roles.append({'RoleName': role['RoleName'], 'Permissions': {'Allow': {}, 'Deny': {}}})

    # Get role permissions
    print('Enumerating permissions for {} roles...'.format(len(roles)))
    for role in roles:
        role['Policies'] = []
        try:
            # Get inline role policies
            policies = []
            if 'Policies' not in role:
                role['Policies'] = []
            try:
                res = client.list_role_policies(
                    RoleName=role['RoleName']
                )
                policies = res['PolicyNames']
                while res.get('IsTruncated'):
                    res = client.list_role_policies(
                        RoleName=role['RoleName'],
                        Marker=res['Marker']
                    )
                    policies += res['PolicyNames']
                for policy in policies:
                    role['Policies'].append({
                        'PolicyName': policy
                    })
            except ClientError as e:
                print('List role policies failed: {}'.format(e))
            # Get document for each inline policy
            for policy in policies:
                try:
                    document = client.get_role_policy(
                        RoleName=role['RoleName'],
                        PolicyName=policy
                    )['PolicyDocument']
                except ClientError as e:
                    print('Get role policy failed: {}'.format(e))
                role = parse_document(document, role)
            # Get attached role policies
            attached_policies = []
            try:
                res = client.list_attached_role_policies(
                    RoleName=role['RoleName']
                )
                attached_policies = res['AttachedPolicies']
                while res.get('IsTruncated'):
                    res = client.list_attached_role_policies(
                        RoleName=role['RoleName'],
                        Marker=res['Marker']
                    )
                    attached_policies += res['AttachedPolicies']
                role['Policies'] += attached_policies
            except ClientError as e:
                print('List attached role policies failed: {}'.format(e))
            role = parse_attached_policies(client, attached_policies, role)
            role.pop('Policies', None)
        except Exception as e:
            print('Error, skipping role {}:\n{}'.format(role['RoleName'], e))
        print('  {}... done!'.format(role['RoleName']))

    # Begin privesc scanning
    all_role_permissions = [
        'iam:AttachRolePolicy',
        'iam:CreateRole',
        'iam:PassRole',
        'iam:PutRolePolicy',
        'iam:UpdateAssumeRolePolicy',
        'lambda:AddPermission',
        'lambda:CreateFunction',
        'lambda:UpdateFunctionCode',
        'lambda:UpdateFunctionConfiguration',
        'sts:AssumeRole',
        'ecr:BatchGetImage',
        'ecr:GetDownloadUrlForLayer'
    ]

    role_escalation_methods = {
        'iam:AttachRolePolicy': {
            'iam:AttachRolePolicy': True
        },
        'iam:CreateRole': {
            'iam:CreateRole': True
        },
        'iam:PassRole': {
            'iam:PassRole': True
        },
        'iam:PutRolePolicy': {
            'iam:PutRolePolicy': True
        },
        'iam:UpdateAssumeRolePolicy': {
            'iam:UpdateAssumeRolePolicy': True
        },
        'lambda:AddPermission': {
            'lambda:AddPermission': True
        },
        'lambda:CreateFunction': {
            'lambda:CreateFunction': True
        },
        'lambda:UpdateFunctionCode': {
            'lambda:UpdateFunctionCode': True
        },
        'lambda:UpdateFunctionConfiguration': {
            'lambda:UpdateFunctionConfiguration': True
        },
        'sts:AssumeRole': {
            'sts:AssumeRole': True
        },
        'ecr:BatchGetImage': {
            'ecr:BatchGetImage': True
        },
        'ecr:GetDownloadUrlForLayer': {
            'ecr:GetDownloadUrlForLayer': True
        }
    }

    for role in roles:
        print('\nRole: {}'.format(role['RoleName']))
        checked_perms = {'Allow': {}, 'Deny': {}}
        if 'Permissions' in role and 'Allow' in role['Permissions']:
            # Are they an admin already?
            if '*' in role['Permissions']['Allow'] and role['Permissions']['Allow']['*']['Resources'] == ['*']:
                if role['Permissions']['Deny'] == {} and role['Permissions']['Allow']['*']['Conditions'] == []:
                    role['CheckedMethods'] = {'admin': {}, 'Confirmed': ['sts:AssumeRole', 'lambda:UpdateFunctionConfiguration', 'iam:PassRole', 'lambda:CreateFunction', 'iam:CreateRole', 'iam:AttachRolePolicy', 'iam:PutRolePolicy'], 'Potential': {}}
                    print('  Already an admin!')
                    continue
                else:
                    role['CheckedMethods'] = {'possible_admin': {}, 'Confirmed': ['sts:AssumeRole', 'lambda:UpdateFunctionConfiguration', 'iam:PassRole', 'lambda:CreateFunction', 'iam:CreateRole', 'iam:AttachRolePolicy', 'iam:PutRolePolicy'], 'Potential': {}}
                    print('  Might already be an admin, check any explicit denies or policy condition keys!')
                    continue
            for perm in all_role_permissions:
                for effect in ['Allow', 'Deny']:
                    if perm in role['Permissions'][effect]:
                        checked_perms[effect][perm] = role['Permissions'][effect][perm]
                    else:
                        for role_perm in role['Permissions'][effect].keys():
                            if '*' in role_perm:
                                pattern = re.compile(role_perm.replace('*', '.*'))
                                if pattern.search(perm) is not None:
                                    checked_perms[effect][perm] = role['Permissions'][effect][role_perm]

        checked_methods = {
            'Potential': [],
            'Confirmed': []
        }

        # Ditch each escalation method that has been confirmed not to be possible
        for method in role_escalation_methods:
            potential = True
            confirmed = True
            for perm in role_escalation_methods[method]:
                # If this permission isn't Allowed, or this permission is Allowed but resource isn't all, then this method won't work
                if perm not in checked_perms['Allow']:
                    potential = confirmed = False
                    break
                # If this permission is Allowed but resource isn't all, then this method won't work
                elif isinstance(checked_perms['Allow'][perm]['Resources'], str):
                    if not (checked_perms['Allow'][perm]['Resources'].endswith("/*") or checked_perms['Allow'][perm]['Resources'].endswith(":*") or checked_perms['Allow'][perm]['Resources'] == "*"):
                        potential = confirmed = False
                        break
                elif isinstance(checked_perms['Allow'][perm]['Resources'], list):
                    for res in checked_perms['Allow'][perm]['Resources']:
                        if isinstance(res, str):
                            if not (res.endswith("/*") or res.endswith(":*") or res == "*"):
                                potential = confirmed = False
                                break
                # Permission is both Denied and Allowed, leave as potential, not confirmed
                if perm in checked_perms['Deny'] and perm in checked_perms['Allow']:
                    confirmed = False
            if confirmed is True:
                print('  CONFIRMED: {}'.format(method))
                checked_methods['Confirmed'].append(method)
            elif potential is True:
                print('  POTENTIAL: {}'.format(method))
                checked_methods['Potential'].append(method)
        role['CheckedMethods'] = checked_methods
        if checked_methods['Potential'] == [] and checked_methods['Confirmed'] == []:
            print('  No methods possible.')
    print("\nTraverse the executive role permissions of the functions in each application.\n")

    cf_client = session.client('cloudformation')
    lambda_client = session.client('lambda')

    Stack_function_escalate_permission = []

    try:
        # list all applications
        response = cf_client.list_stacks(StackStatusFilter=['CREATE_COMPLETE', 'UPDATE_COMPLETE'])
        stacks = response['StackSummaries']

        while 'NextToken' in response:
            response = cf_client.list_stacks(NextToken=response['NextToken'])
            stacks.extend(response['StackSummaries'])

        for stack in stacks:
            stack_name = stack['StackName']
            print(f"Application: {stack_name}")
            function_escalate_permission = []
            try:
                resources = cf_client.list_stack_resources(StackName=stack_name)['StackResourceSummaries']

                lambda_functions = [res for res in resources if res['ResourceType'] == 'AWS::Lambda::Function']

                # list all functions
                for func in lambda_functions:
                    function_name = func['PhysicalResourceId']
                    function_confirmed = []
                    print(f"  Function: {function_name}")

                    try:
                        function_config = lambda_client.get_function(FunctionName=function_name)
                        role_arn = function_config['Configuration']['Role']
                        print(f"    Role ARN: {role_arn}")
                        try:
                            role_name = role_arn.split(':')[-1].split('/')[-1]
                        except Exception as e:
                            return f"Error parsing ARN: {str(e)}"
                        for role in roles:
                            if role['RoleName'] == role_name:
                                safe = True
                                for method in role_escalation_methods:
                                    if 'admin' in role['CheckedMethods']:
                                        print('  Already an admin!')
                                        print('  CONFIRMED: {}'.format(role['CheckedMethods']['Confirmed']))
                                        function_confirmed += role['CheckedMethods']['Confirmed']
                                        safe = False
                                        break
                                    elif 'possible_admin' in role['CheckedMethods']:
                                        print('  Might already be an admin, check any explicit denies or policy condition keys!')
                                        print('  CONFIRMED: {}'.format(role['CheckedMethods']['Confirmed']))
                                        function_confirmed += role['CheckedMethods']['Confirmed']
                                        safe = False
                                        break
                                    elif method in role['CheckedMethods']['Confirmed']:
                                        print('  CONFIRMED: {}'.format(role['CheckedMethods']['Confirmed']))
                                        function_confirmed += role['CheckedMethods']['Confirmed']
                                        safe = False
                                        break
                                    elif method in role['CheckedMethods']['Potential']:
                                        print('  POTENTIAL: {}'.format(role['CheckedMethods']['Potential']))
                                        safe = False
                                        break
                                if safe:
                                    print('    it is safe!')
                        function_confirmed = list(set(function_confirmed))
                        function_escalate_permission.append(
                            {'FunctionName': function_name, 'RoleArn': role_arn, 'Confirmed': function_confirmed})
                    except ClientError as e:
                        print(f"    Error getting function role: {e}")
                    print("    " + "-" * 40)
                print("=" * 60)
                Stack_function_escalate_permission.append(
                    {'StackName': stack_name, 'Function': function_escalate_permission})
            except ClientError as e:
                print(f"  Error listing stack resources: {e}")
        #print(Stack_function_escalate_permission)
    except ClientError as e:
        print(f"Error listing CloudFormation stacks: {e}")

    function_escalation_method1 = {
        'sts:AssumeRole': {
            'sts:AssumeRole': True
        },
        'iam:CreateRole+iam:AttachRolePolicy': {
            'iam:CreateRole': True,
            'iam:AttachRolePolicy': True
        },
        'iam:PutRolePolicy': {
            'iam:PutRolePolicy': True
        },
        'iam:UpdateAssumeRolePolicy': {
            'iam:UpdateAssumeRolePolicy': True
        }
    }

    function_escalation_method2 = {
        'iam:PassRole+lambda:CreateFunction': {
            'iam:PassRole': True,
            'lambda:CreateFunction': True
        },
        'lambda:UpdateFunctionCode': {
            'lambda:UpdateFunctionCode': True
        }
    }

    # check strategies 1 and 2
    print('\nScan the attack paths in the account.\n')

    all_escalate_privilege = []

    for stack in Stack_function_escalate_permission:
        for func in stack['Function']:
            all_escalate_privilege.extend(func['Confirmed'])

    all_escalate_privilege = list(set(all_escalate_privilege))
    escalation_group_all = []
    escalation_group_all.extend(check_escalation_method1(all_escalate_privilege, function_escalation_method1,
                                                      "function_escalation_method1"))
    escalation_group_all.extend(
        check_escalation_method2(all_escalate_privilege, function_escalation_method1, function_escalation_method2,
                                 "function_escalation_method2"))
    all_permission_location = []
    if not escalation_group_all:
        print("Don't find privilege escalation path.")
    if escalation_group_all:
        print("The privilege escalation path in the account:")
        for method in escalation_group_all:
            print(f"    {method}")
        #print("\nDangerous permissions and their locations in the escalation path:")
        processed_permissions = set() #track processed permissions
        for method in escalation_group_all:
            permissions = extract_permissions_from_method(method, function_escalation_method1, function_escalation_method2)
            for perm in permissions:
                permission_location = []
                if perm not in processed_permissions: #Only permissions that are not output are processed
                    #print(f"\n  Permission: {perm}")
                    for stack in Stack_function_escalate_permission:
                        for func in stack['Function']:
                            if perm in func['Confirmed']:
                                #print(f"    Application: {stack['StackName']}, Function: {func['FunctionName']}, RoleArn: {func['RoleArn']}")
                                permission_location.append({"Application" : stack['StackName'], "Function" : func['FunctionName']})
                    processed_permissions.add(perm)
                    all_permission_location.append({"Permission": perm, "location": permission_location})
        #print(all_permission_location)
        print("\nHere are function-based attack paths in the account.\n")

        updated_escalation_group = get_function_based_path(escalation_group_all,all_permission_location)
        for updated_path in updated_escalation_group:
            print(updated_path)

    print("=" * 60)
    print('\nDivide all applications into two groups, combine the resources of the two groups respectively, and detect the attack path.')
    stack_names = [stack['StackName'] for stack in Stack_function_escalate_permission]
    total_stacks = len(stack_names)
    combinations_list = generate_combinations(stack_names, total_stacks)

    print(f"There are {len(combinations_list)} combinations in total. But only the following combination can fulfill the premise of cross-account contamination.")
    # Record the number of valid combinations
    num = 0
    for i, (group1, group2) in enumerate(combinations_list, 1):
        all_permission_location1 = []
        all_permission_location2 = []

        confirmed_group1 = get_confirmed_union(group1, Stack_function_escalate_permission)
        confirmed_group2 = get_confirmed_union(group2, Stack_function_escalate_permission)

        # identification of function_escalation_method1 or function_escalation_method2
        escalation_group1 = []
        escalation_group1.extend(check_escalation_method1(confirmed_group1, function_escalation_method1,
                                                         "function_escalation_method1"))
        escalation_group1.extend(
            check_escalation_method2(confirmed_group1, function_escalation_method1, function_escalation_method2, "function_escalation_method2"))

        escalation_group2 = []
        escalation_group2.extend(check_escalation_method1(confirmed_group2, function_escalation_method1,
                                                         "function_escalation_method1"))
        escalation_group2.extend(
            check_escalation_method2(confirmed_group2, function_escalation_method1, function_escalation_method2, "function_escalation_method2"))

        # Check whether the administrator of account 1 can be obtained. If not, delete the combination
        if not escalation_group1:
            continue

        # list valid combinations
        else:
            num += 1
            if num != 1:
                print("=" * 60)
            print(f"\nCombination {num}:")
            print("\nAccount 1:")

            print("  The account contains the following applications:")
            output1 = ', '.join(group1)
            print("    "+output1)

            print(f"  Confirmed escalated permission: \n    {confirmed_group1}")

            if escalation_group1:
                print("\n  The privilege escalation path in Account 1:")
                for method in escalation_group1:
                    print(f"    {method}")

                #print("\n  Dangerous permissions and their locations in this combination (Account 1):")
                processed_permissions = set()
                for method in escalation_group1:
                    permissions = extract_permissions_from_method(method, function_escalation_method1, function_escalation_method2)
                    for perm in permissions:
                        permission_location1 = []
                        if perm not in processed_permissions:
                            #print(f"\n    Permission: {perm}")
                            for stack in Stack_function_escalate_permission:
                                if stack['StackName'] in group1:
                                    for func in stack['Function']:
                                        if perm in func['Confirmed']:
                                            #print(f"      Application: {stack['StackName']}, Function: {func['FunctionName']}, RoleArn: {func['RoleArn']}")
                                            permission_location1.append({"Application": stack['StackName'], "Function": func['FunctionName']})
                            processed_permissions.add(perm)
                            all_permission_location1.append({"Permission": perm, "location": permission_location1})

                print("\n  Here are function-based attack paths in Account 1.\n")
                updated_escalation_group1 = get_function_based_path(escalation_group1, all_permission_location1)
                for updated_path in updated_escalation_group1:
                    print(updated_path)

            print("\nAccount 2:")

            print("  The account contains the following applications:")
            output2 = ', '.join(group2)
            print("    " + output2)

            print(f"  Confirmed escalated permission: \n    {confirmed_group2}")

            if escalation_group2:
                print("\n  The privilege escalation path in Account 2:")
                for method in escalation_group2:
                    print(f"    {method}")

                #print("\n  Dangerous permissions and their locations in this combination (Account 2):")
                processed_permissions = set()
                for method in escalation_group2:
                    permissions = extract_permissions_from_method(method, function_escalation_method1, function_escalation_method2)
                    for perm in permissions:
                        permission_location2 = []
                        if perm not in processed_permissions:
                            #print(f"\n    Permission: {perm}")
                            for stack in Stack_function_escalate_permission:
                                if stack['StackName'] in group2:
                                    for func in stack['Function']:
                                        if perm in func['Confirmed']:
                                            #print(f"      Application: {stack['StackName']}, Function: {func['FunctionName']}, RoleArn: {func['RoleArn']}")
                                            permission_location2.append({"Application": stack['StackName'], "Function": func['FunctionName']})
                            processed_permissions.add(perm)
                            all_permission_location2.append({"Permission": perm, "location": permission_location2})

                print("\n  Here are function-based attack paths in Account 2.\n")
                updated_escalation_group2 = get_function_based_path(escalation_group2, all_permission_location2)
                for updated_path in updated_escalation_group2:
                    print(updated_path)

            # Check whether account 1 can infect account 2 through the Layer
            if 'lambda:UpdateFunctionConfiguration' in confirmed_group2 and escalation_group1:
                print("\n  Account 2 can be infected by Account 1,because Account 2 have lambda:UpdateFunctionConfiguration.")
                # Check whether account 1 can obtain account 2's administrator privileges
                if escalation_group2:
                    print("  Account 1 can obtain Account 2's administrator privileges through the layer.")
                print(f"\n    Permission: lambda:UpdateFunctionConfiguration")
                for stack in Stack_function_escalate_permission:
                    if stack['StackName'] in group2:
                        for func in stack['Function']:
                            if 'lambda:UpdateFunctionConfiguration' in func['Confirmed']:
                                print(f"      Application: {stack['StackName']}, Function: {func['FunctionName']}, RoleArn: {func['RoleArn']}")

            # Check whether account 1 can infect account 2 through the ECR
            if 'ecr:BatchGetImage' in confirmed_group2 and 'ecr:GetDownloadUrlForLayer' in confirmed_group2 and escalation_group1:
                if 'lambda:CreateFunction' in confirmed_group2 and 'iam:PassRole' in confirmed_group2:
                    print("\n  Account 2 can be infected by Account 1,because Account 2 have ecr:BatchGetImage, ecr:GetDownloadUrlForLayer,lambda:CreateFunction and iam:PassRole.")
                    # Check whether account 1 can obtain account 2's administrator privileges
                    if escalation_group2:
                            print("  Account 1 can obtain Account 2's administrator privileges through ECR.")
                    permissions = ['ecr:BatchGetImage','ecr:GetDownloadUrlForLayer','lambda:CreateFunction', 'iam:PassRole']
                    for perm in permissions:
                        print(f"\n    Permission: {perm}")
                        for stack in Stack_function_escalate_permission:
                            if stack['StackName'] in group2:
                                for func in stack['Function']:
                                    if perm in func['Confirmed']:
                                        print(f"      Application: {stack['StackName']}, Function: {func['FunctionName']}, RoleArn: {func['RoleArn']}")

    print('\nPrivilege escalation check completed.')

# get function_based attack path
def get_function_based_path(escalation_group_all,all_permission_location):
    permission_to_locations = {}
    for item in all_permission_location:
        permission = item['Permission']
        locations = item['location']
        permission_to_locations[permission] = [f"{{{permission}}}{loc['Application']}:{loc['Function']}" for loc in
                                               locations]

    updated_escalation_group = []
    for path in escalation_group_all:
        parts = path.split(" -> ")
        first_part = parts[0]
        first_permissions = first_part.split("'")[1].split("+")
        replaced_first_permissions_list = []

        for perm in first_permissions:
            if perm in permission_to_locations:
                replaced_first_permissions_list.append(permission_to_locations[perm]) 
            else:
                replaced_first_permissions_list.append([f"{{{perm}}}{perm}"]) 

        if len(parts) > 1 and "'" in parts[1]:
            second_part = parts[1]
            second_permissions = second_part.split("'")[1].split("+")
            replaced_second_permissions_list = []

            for perm in second_permissions:
                if perm in permission_to_locations:
                    replaced_second_permissions_list.append(permission_to_locations[perm]) 
                else:
                    replaced_second_permissions_list.append([f"{{{perm}}}{perm}"])  

            for first_combination in product(*replaced_first_permissions_list):
                for second_combination in product(*replaced_second_permissions_list):
                    new_first_permissions = "+".join(first_combination)
                    new_second_permissions = "+".join(second_combination)
                    updated_path = f"    confirm: {new_first_permissions} -> '{new_second_permissions}' -> {parts[2]}"
                    updated_escalation_group.append(updated_path)

        else:

            for first_combination in product(*replaced_first_permissions_list):
                new_first_permissions = "+".join(first_combination)
                updated_path = f"    confirm: {new_first_permissions} -> {parts[1]}"
                updated_escalation_group.append(updated_path)
    return updated_escalation_group

# generate all combinations
def generate_combinations(stack_list, n):
    all_combinations = []
    for i in range(1, n):
        for combo in combinations(stack_list, i):
            group1 = list(combo)
            group2 = [x for x in stack_list if x not in group1]
            all_combinations.append((group1, group2))
    return all_combinations

# Compute the union of Confirmed permissions for a group
def get_confirmed_union(group, stack_data):
    confirmed_set = set()
    for stack_name in group:
        for stack in stack_data:
            if stack['StackName'] == stack_name:
                for func in stack['Function']:
                    confirmed_set.update(func['Confirmed'])
    return list(confirmed_set)

def check_escalation_method1(confirmed_list, escalation_method1, method_type):
    confirmed_set = set(confirmed_list)
    matched_methods = []
    for method, required_permissions in escalation_method1.items():
        required_set = set(required_permissions.keys())
        if required_set.issubset(confirmed_set):
            matched_methods.append(f"confirm: '{method}' -> {method_type}")
    return matched_methods

def check_escalation_method2(confirmed_list, escalation_method1, escalation_method2, method_type):
    confirmed_set = set(confirmed_list)
    matched_methods = []
    for method2, required_permissions2 in escalation_method2.items():
        required_set2 = set(required_permissions2.keys())
        if required_set2.issubset(confirmed_set):
            for method1, required_permissions1 in escalation_method1.items():
                required_set1 = set(required_permissions1.keys())
                if required_set1.issubset(confirmed_set):
                    matched_methods.append(f"confirm: '{method2}' -> '{method1}' -> {method_type}")
    return matched_methods

#Extract the permissions from the attack path
def extract_permissions_from_method(method, escalation_method1, escalation_method2):
    permissions = []
    # Extract the method name (assuming the format "confirm: 'method_name' ->..." Or "confirm: 'method2' -> 'method1' ->...")
    method_parts = method.split(" -> ")
    if "function_escalation_method2" in method_parts[-1]:
        method2_name = method_parts[0].split("'")[1]
        method1_name = method_parts[1].split("'")[1]
        permissions.extend(list(escalation_method2[method2_name].keys()))
        permissions.extend(list(escalation_method1[method1_name].keys()))
    elif "function_escalation_method1" in method_parts[-1]:
        method1_name = method_parts[0].split("'")[1]
        permissions.extend(list(escalation_method1[method1_name].keys()))
    return permissions

# Pull permissions from each policy document
def parse_attached_policies(client, attached_policies, user):
    for policy in attached_policies:
        document = get_attached_policy(client, policy['PolicyArn'])
        user = parse_document(document, user)
    return user


# Get the policy document of an attached policy
def get_attached_policy(client, policy_arn):
    try:
        policy = client.get_policy(
            PolicyArn=policy_arn
        )['Policy']
        version = policy['DefaultVersionId']
        can_get = True
    except ClientError as e:
        print('Get policy failed: {}'.format(e))
        return False

    try:
        if can_get:
            document = client.get_policy_version(
                PolicyArn=policy_arn,
                VersionId=version
            )['PolicyVersion']['Document']
            return document
    except ClientError as e:
        print('Get policy version failed: {}'.format(e))
        return False


# Loop permissions and the resources they apply to
def parse_document(document, user):
    if isinstance(document['Statement'], dict):
        document['Statement'] = [document['Statement']]

    for statement in document['Statement']:
        if statement['Effect'] == 'Allow':
            if 'Action' in statement and isinstance(statement['Action'],
                                                    list):  # Check if the action is a single action (str) or multiple (list)
                statement['Action'] = list(
                    set(statement['Action']))  # Remove duplicates to stop the circular reference JSON error
                for action in statement['Action']:
                    if action in user['Permissions']['Allow']:
                        if isinstance(statement['Resource'], list):
                            user['Permissions']['Allow'][action]['Resources'] += statement['Resource']
                        else:
                            user['Permissions']['Allow'][action]['Resources'].append(statement['Resource'])
                    else:
                        user['Permissions']['Allow'][action] = {'Resources': [], 'Conditions': []}
                        if isinstance(statement['Resource'], list):
                            user['Permissions']['Allow'][action]['Resources'] = statement['Resource']
                        else:
                            user['Permissions']['Allow'][action]['Resources'] = [statement['Resource']]
                    if 'Condition' in statement:
                        user['Permissions']['Allow'][action]['Conditions'].append(statement['Condition'])
                    user['Permissions']['Allow'][action]['Resources'] = list(
                        set(user['Permissions']['Allow'][action]['Resources']))  # Remove duplicate resources
            elif 'Action' in statement and isinstance(statement['Action'], str):
                if statement['Action'] in user['Permissions']['Allow']:
                    if isinstance(statement['Resource'], list):
                        user['Permissions']['Allow'][statement['Action']]['Resources'] += statement['Resource']
                    else:
                        user['Permissions']['Allow'][statement['Action']]['Resources'].append(statement['Resource'])
                else:
                    user['Permissions']['Allow'][statement['Action']] = {'Resources': [], 'Conditions': []}
                    if isinstance(statement['Resource'], list):
                        user['Permissions']['Allow'][statement['Action']]['Resources'] = statement['Resource']
                    else:
                        user['Permissions']['Allow'][statement['Action']]['Resources'] = [
                            statement['Resource']]  # Make sure that resources are always arrays
                if 'Condition' in statement:
                    user['Permissions']['Allow'][statement['Action']]['Conditions'].append(statement['Condition'])
                user['Permissions']['Allow'][statement['Action']]['Resources'] = list(
                    set(user['Permissions']['Allow'][statement['Action']]['Resources']))  # Remove duplicate resources

            if 'NotAction' in statement and isinstance(statement['NotAction'],
                                                       list):  # NotAction is reverse, so allowing a NotAction is denying that action basically
                statement['NotAction'] = list(
                    set(statement['NotAction']))  # Remove duplicates to stop the circular reference JSON error
                for not_action in statement['NotAction']:
                    if '!{}'.format(not_action) in user['Permissions']['Allow']:
                        if isinstance(statement['Resource'], list):
                            user['Permissions']['Allow']['!{}'.format(not_action)]['Resources'] += statement['Resource']
                        else:
                            user['Permissions']['Allow']['!{}'.format(not_action)]['Resources'].append(
                                statement['Resource'])
                    else:
                        user['Permissions']['Allow']['!{}'.format(not_action)] = {'Resources': [], 'Conditions': []}
                        if isinstance(statement['Resource'], list):
                            user['Permissions']['Allow']['!{}'.format(not_action)]['Resources'] = statement['Resource']
                        else:
                            user['Permissions']['Allow']['!{}'.format(not_action)]['Resources'] = [
                                statement['Resource']]
                    if 'Condition' in statement:
                        user['Permissions']['Allow']['!{}'.format(not_action)]['Conditions'].append(
                            statement['Condition'])
                    user['Permissions']['Allow']['!{}'.format(not_action)]['Resources'] = list(set(
                        user['Permissions']['Allow']['!{}'.format(not_action)][
                            'Resources']))  # Remove duplicate resources
            elif 'NotAction' in statement and isinstance(statement['NotAction'], str):
                if '!{}'.format(statement['NotAction']) in user['Permissions']['Allow']:
                    if isinstance(statement['Resource'], list):
                        user['Permissions']['Allow']['!{}'.format(statement['NotAction'])]['Resources'] += statement[
                            'Resource']
                    else:
                        user['Permissions']['Allow']['!{}'.format(statement['NotAction'])]['Resources'].append(
                            statement['Resource'])
                else:
                    user['Permissions']['Allow']['!{}'.format(statement['NotAction'])] = {'Resources': [],
                                                                                          'Conditions': []}
                    if isinstance(statement['Resource'], list):
                        user['Permissions']['Allow']['!{}'.format(statement['NotAction'])]['Resources'] = statement[
                            'Resource']
                    else:
                        user['Permissions']['Allow']['!{}'.format(statement['NotAction'])]['Resources'] = [
                            statement['Resource']]  # Make sure that resources are always arrays
                if 'Condition' in statement:
                    user['Permissions']['Allow']['!{}'.format(statement['NotAction'])]['Conditions'].append(
                        statement['Condition'])
                user['Permissions']['Allow']['!{}'.format(statement['NotAction'])]['Resources'] = list(set(
                    user['Permissions']['Allow']['!{}'.format(statement['NotAction'])][
                        'Resources']))  # Remove duplicate resources

        if statement['Effect'] == 'Deny':
            if 'Action' in statement and isinstance(statement['Action'], list):
                statement['Action'] = list(
                    set(statement['Action']))  # Remove duplicates to stop the circular reference JSON error
                for action in statement['Action']:
                    if action in user['Permissions']['Deny']:
                        if isinstance(statement['Resource'], list):
                            user['Permissions']['Deny'][action]['Resources'] += statement['Resource']
                        else:
                            user['Permissions']['Deny'][action]['Resources'].append(statement['Resource'])
                    else:
                        user['Permissions']['Deny'][action] = {'Resources': [], 'Conditions': []}
                        if isinstance(statement['Resource'], list):
                            user['Permissions']['Deny'][action]['Resources'] = statement['Resource']
                        else:
                            user['Permissions']['Deny'][action]['Resources'] = [statement['Resource']]
                    if 'Condition' in statement:
                        user['Permissions']['Deny'][action]['Conditions'].append(statement['Condition'])
                    user['Permissions']['Deny'][action]['Resources'] = list(
                        set(user['Permissions']['Deny'][action]['Resources']))  # Remove duplicate resources
            elif 'Action' in statement and isinstance(statement['Action'], str):
                if statement['Action'] in user['Permissions']['Deny']:
                    if isinstance(statement['Resource'], list):
                        user['Permissions']['Deny'][statement['Action']]['Resources'] += statement['Resource']
                    else:
                        user['Permissions']['Deny'][statement['Action']]['Resources'].append(statement['Resource'])
                else:
                    user['Permissions']['Deny'][statement['Action']] = {'Resources': [], 'Conditions': []}
                    if isinstance(statement['Resource'], list):
                        user['Permissions']['Deny'][statement['Action']]['Resources'] = statement['Resource']
                    else:
                        user['Permissions']['Deny'][statement['Action']]['Resources'] = [
                            statement['Resource']]  # Make sure that resources are always arrays
                if 'Condition' in statement:
                    user['Permissions']['Deny'][statement['Action']]['Conditions'].append(statement['Condition'])
                user['Permissions']['Deny'][statement['Action']]['Resources'] = list(
                    set(user['Permissions']['Deny'][statement['Action']]['Resources']))  # Remove duplicate resources

            if 'NotAction' in statement and isinstance(statement['NotAction'],
                                                       list):  # NotAction is reverse, so allowing a NotAction is denying that action basically
                statement['NotAction'] = list(
                    set(statement['NotAction']))  # Remove duplicates to stop the circular reference JSON error
                for not_action in statement['NotAction']:
                    if '!{}'.format(not_action) in user['Permissions']['Deny']:
                        if isinstance(statement['Resource'], list):
                            user['Permissions']['Deny']['!{}'.format(not_action)]['Resources'] += statement['Resource']
                        else:
                            user['Permissions']['Deny']['!{}'.format(not_action)]['Resources'].append(
                                statement['Resource'])
                    else:
                        user['Permissions']['Deny']['!{}'.format(not_action)] = {'Resources': [], 'Conditions': []}
                        if isinstance(statement['Resource'], list):
                            user['Permissions']['Deny']['!{}'.format(not_action)]['Resources'] = statement['Resource']
                        else:
                            user['Permissions']['Deny']['!{}'.format(not_action)]['Resources'] = [statement['Resource']]
                    if 'Condition' in statement:
                        user['Permissions']['Deny']['!{}'.format(not_action)]['Conditions'].append(
                            statement['Condition'])
                    user['Permissions']['Deny']['!{}'.format(not_action)]['Resources'] = list(set(
                        user['Permissions']['Deny']['!{}'.format(not_action)][
                            'Resources']))  # Remove duplicate resources
            elif 'NotAction' in statement and isinstance(statement['NotAction'], str):
                if '!{}'.format(statement['NotAction']) in user['Permissions']['Deny']:
                    if isinstance(statement['Resource'], list):
                        user['Permissions']['Deny']['!{}'.format(statement['NotAction'])]['Resources'] += statement[
                            'Resource']
                    else:
                        user['Permissions']['Deny']['!{}'.format(statement['NotAction'])]['Resources'].append(
                            statement['Resource'])
                else:
                    user['Permissions']['Deny']['!{}'.format(statement['NotAction'])] = {'Resources': [],
                                                                                         'Conditions': []}
                    if isinstance(statement['Resource'], list):
                        user['Permissions']['Deny']['!{}'.format(statement['NotAction'])]['Resources'] = statement[
                            'Resource']
                    else:
                        user['Permissions']['Deny']['!{}'.format(statement['NotAction'])]['Resources'] = [
                            statement['Resource']]  # Make sure that resources are always arrays
                if 'Condition' in statement:
                    user['Permissions']['Deny']['!{}'.format(statement['NotAction'])]['Conditions'].append(
                        statement['Condition'])
                user['Permissions']['Deny']['!{}'.format(statement['NotAction'])]['Resources'] = list(set(
                    user['Permissions']['Deny']['!{}'.format(statement['NotAction'])][
                        'Resources']))  # Remove duplicate resources
    return user


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='This script will fetch permissions for all IAM users and roles and then scan for permission misconfigurations to see what privilege escalation methods each are vulnerable to. Available attack paths will be output to a .csv file in the same directory.')

    parser.add_argument('-p', '--profile', required=False, default=None,
                        help='The AWS CLI profile to use for making API calls. This is usually stored under ~/.aws/credentials. You will be prompted by default.')

    args = parser.parse_args()
    main(args)
