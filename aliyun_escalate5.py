#!/usr/bin/env python
from aliyunsdkcore.client import AcsClient
from aliyunsdkram.request.v20150501 import ListRolesRequest, GetPolicyRequest, ListPoliciesForRoleRequest, GetPolicyVersionRequest
from fc2.client import Client as FCClient
from itertools import combinations,product
import json
import re

#output services, functions and their roles
def print_service_function_permissions(service_function_permissions):
    for service in service_function_permissions:
        stack_name = service.get('StackName', 'Unknown Service')
        print(f"Service: {stack_name}")

        for function in service['Function']:
            function_name = function.get('FunctionName', 'Unknown Function')
            role_arn = function.get('RoleArn', 'No Role Assigned')
            confirmed = function.get('Confirmed', [])

            print(f"  Function: {function_name}")
            print(f"    Role ARN: {role_arn}")
            print(f"  CONFIRMED: {confirmed}")
            if function != service['Function'][-1]:
                print("    " + "-" * 40)

        if service != service_function_permissions[-1]:
            print()

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


# extract RoleName from RoleArn
def extract_role_name(role_arn):
    if not role_arn or 'role/' not in role_arn:
        return None
    # RoleArn 格式为 acs:ram::account-id:role/role-name
    return role_arn.split('role/')[-1].lower()


# add 'confirm' of checkmethod to service_function_role
def update_service_function_role(service_function_role, roles):
    role_confirmed_map = {role['RoleName'].lower(): role['CheckedMethods']['Confirmed'] for role in roles}

    for service in service_function_role:
        for function in service['Function']:
            role_arn = function.get('RoleArn', '')
            role_name = extract_role_name(role_arn)

            if role_name and role_name in role_confirmed_map:
                function['Confirmed'] = role_confirmed_map[role_name]
            else:
                function['Confirmed'] = []

    return service_function_role

# Initialize the function compute client
def create_fc_client(access_key_id, access_key_secret, endpoint):
    print(f"\nCreating FC Client with endpoint: {endpoint}")
    client = FCClient(
        endpoint=endpoint,
        accessKeyID=access_key_id,
        accessKeySecret=access_key_secret
    )
    print("FC Client created successfully.")
    return client

# Get all services and list functions and their roles
def list_services_and_functions(fc_client):
    try:
        print("Listing services and their functions...\n")
        limit = 100
        next_token = None
        service_function_map = {}
        service_function_role = []

        # get all services
        while True:
            response = fc_client.list_services(limit=limit, nextToken=next_token)
            services = response.data.get('services', [])
            if not services:
                print("No services found.")
                break

            for service in services:
                service_name = service.get('serviceName', 'unknown_service')
                service_role = service.get('role', 'Not Set')  # service role
                service_function_map[service_name] = {'service_role': service_role, 'functions': []}
                function_roles = []
                # get all functions
                func_next_token = None
                while True:
                    func_response = fc_client.list_functions(
                        serviceName=service_name,
                        limit=limit,
                        nextToken=func_next_token
                    )
                    functions = func_response.data.get('functions', [])
                    if not functions:
                        break

                    for function in functions:
                        function_name = function.get('functionName', 'unknown_function')
                        # get function role
                        function_role = function.get('role', None)
                        # Identify the roles that actually work
                        effective_role = function_role if function_role else service_role

                        service_function_map[service_name]['functions'].append({
                            'name': function_name,
                            'id': function.get('functionId', 'N/A'),
                            'function_role': function_role if function_role else 'Not Set',
                            'effective_role': effective_role
                        })
                        function_roles.append({
                                'FunctionName': function_name,
                                'RoleArn': effective_role
                            })

                    func_next_token = func_response.data.get('nextToken', None)
                    if not func_next_token:
                        break

                service_function_role.append({
                    'StackName': service_name,
                    'Function': function_roles
                })

            next_token = response.data.get('nextToken', None)
            if not next_token:
                break
        '''
        for service_name, info in service_function_map.items():
            print(f"\nApplication/Service: {service_name}")
            print(f"Service Default Role: {info['service_role']}")
            print("Functions:")
            if not info['functions']:
                print("  No functions found in this service.")
            else:
                for func in info['functions']:
                    print(f"  --Function Name: {func['name']}")
                    print(f"    Function ID: {func['id']}")
                    print(f"    Function-Level Role: {func['function_role']}")
                    print(f"    Effective Role: {func['effective_role']}")
        '''
        return service_function_role

    except Exception as e:
        print(f"Unexpected error: {e}")
        return []

# Pull permissions from each policy document
def parse_attached_policies(client, attached_policies, user):
    for policy in attached_policies:
        document = get_attached_policy(client, policy['PolicyName'])
        if document:
            try:
                document = json.loads(document)
            except json.JSONDecodeError as e:
                print(f"[!] Failed to parse AssumeRolePolicyDocument for role {role['RoleName']}: {e}")
            user = parse_document(document, user)
    return user

# Get the policy document of an attached policy
def get_attached_policy(client, policy_name):
    policy_types = ['Custom', 'System']

    for policy_type in policy_types:
        try:
            request = GetPolicyRequest.GetPolicyRequest()
            request.set_PolicyName(policy_name)
            request.set_PolicyType(policy_type)
            response = client.do_action_with_exception(request)
            policy = json.loads(response.decode('utf-8'))

            if 'Policy' not in policy:
                print(f"[!] Policy {policy_name} does not have a default version.")
                continue  #  Try the next policy type

            version = policy['Policy']['DefaultVersion']

            request = GetPolicyVersionRequest.GetPolicyVersionRequest()
            request.set_PolicyName(policy_name)
            request.set_PolicyType(policy_type)
            request.set_VersionId(version)
            response = client.do_action_with_exception(request)
            policy_version = json.loads(response.decode('utf-8'))
            return policy_version['PolicyVersion']['PolicyDocument']

        except:
            #print(f"[!] Failed to get {policy_type} policy or policy version for {policy_name}: {e}")
            continue  # Try the next policy type

    # If all policy types are tried and failed
    print(f"[!] Failed to get policy {policy_name} with both 'System' and 'Custom' types.")
    return None

# Loop permissions and the resources they apply to
def parse_document(document, user):
    if isinstance(document['Statement'], dict):
        document['Statement'] = [document['Statement']]

    for statement in document['Statement']:
        if statement['Effect'] == 'Allow':
            if 'Action' in statement and isinstance(statement['Action'], list):  # Check if the action is a single action (str) or multiple (list)
                statement['Action'] = list(set(statement['Action']))  # Remove duplicates to stop the circular reference JSON error
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
                    user['Permissions']['Allow'][action]['Resources'] = list(set(user['Permissions']['Allow'][action]['Resources']))  # Remove duplicate resources
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
                        user['Permissions']['Allow'][statement['Action']]['Resources'] = [statement['Resource']]  # Make sure that resources are always arrays
                if 'Condition' in statement:
                    user['Permissions']['Allow'][statement['Action']]['Conditions'].append(statement['Condition'])
                user['Permissions']['Allow'][statement['Action']]['Resources'] = list(set(user['Permissions']['Allow'][statement['Action']]['Resources']))  # Remove duplicate resources

            if 'NotAction' in statement and isinstance(statement['NotAction'], list):  # NotAction is reverse, so allowing a NotAction is denying that action basically
                statement['NotAction'] = list(set(statement['NotAction']))  # Remove duplicates to stop the circular reference JSON error
                for not_action in statement['NotAction']:
                    if '!{}'.format(not_action) in user['Permissions']['Allow']:
                        if isinstance(statement['Resource'], list):
                            user['Permissions']['Allow']['!{}'.format(not_action)]['Resources'] += statement['Resource']
                        else:
                            user['Permissions']['Allow']['!{}'.format(not_action)]['Resources'].append(statement['Resource'])
                    else:
                        user['Permissions']['Allow']['!{}'.format(not_action)] = {'Resources': [], 'Conditions': []}
                        if isinstance(statement['Resource'], list):
                            user['Permissions']['Allow']['!{}'.format(not_action)]['Resources'] = statement['Resource']
                        else:
                            user['Permissions']['Allow']['!{}'.format(not_action)]['Resources'] = [statement['Resource']]
                    if 'Condition' in statement:
                        user['Permissions']['Allow']['!{}'.format(not_action)]['Conditions'].append(statement['Condition'])
                    user['Permissions']['Allow']['!{}'.format(not_action)]['Resources'] = list(set(user['Permissions']['Allow']['!{}'.format(not_action)]['Resources']))  # Remove duplicate resources
            elif 'NotAction' in statement and isinstance(statement['NotAction'], str):
                if '!{}'.format(statement['NotAction']) in user['Permissions']['Allow']:
                    if isinstance(statement['Resource'], list):
                        user['Permissions']['Allow']['!{}'.format(statement['NotAction'])]['Resources'] += statement['Resource']
                    else:
                        user['Permissions']['Allow']['!{}'.format(statement['NotAction'])]['Resources'].append(statement['Resource'])
                else:
                    user['Permissions']['Allow']['!{}'.format(statement['NotAction'])] = {'Resources': [], 'Conditions': []}
                    if isinstance(statement['Resource'], list):
                        user['Permissions']['Allow']['!{}'.format(statement['NotAction'])]['Resources'] = statement['Resource']
                    else:
                        user['Permissions']['Allow']['!{}'.format(statement['NotAction'])]['Resources'] = [statement['Resource']]  # Make sure that resources are always arrays
                if 'Condition' in statement:
                    user['Permissions']['Allow']['!{}'.format(statement['NotAction'])]['Conditions'].append(statement['Condition'])
                user['Permissions']['Allow']['!{}'.format(statement['NotAction'])]['Resources'] = list(set(user['Permissions']['Allow']['!{}'.format(statement['NotAction'])]['Resources']))  # Remove duplicate resources

        if statement['Effect'] == 'Deny':
            if 'Action' in statement and isinstance(statement['Action'], list):
                statement['Action'] = list(set(statement['Action']))  # Remove duplicates to stop the circular reference JSON error
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
                    user['Permissions']['Deny'][action]['Resources'] = list(set(user['Permissions']['Deny'][action]['Resources']))  # Remove duplicate resources
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
                        user['Permissions']['Deny'][statement['Action']]['Resources'] = [statement['Resource']]  # Make sure that resources are always arrays
                if 'Condition' in statement:
                    user['Permissions']['Deny'][statement['Action']]['Conditions'].append(statement['Condition'])
                user['Permissions']['Deny'][statement['Action']]['Resources'] = list(set(user['Permissions']['Deny'][statement['Action']]['Resources']))  # Remove duplicate resources

            if 'NotAction' in statement and isinstance(statement['NotAction'], list):  # NotAction is reverse, so allowing a NotAction is denying that action basically
                statement['NotAction'] = list(set(statement['NotAction']))  # Remove duplicates to stop the circular reference JSON error
                for not_action in statement['NotAction']:
                    if '!{}'.format(not_action) in user['Permissions']['Deny']:
                        if isinstance(statement['Resource'], list):
                            user['Permissions']['Deny']['!{}'.format(not_action)]['Resources'] += statement['Resource']
                        else:
                            user['Permissions']['Deny']['!{}'.format(not_action)]['Resources'].append(statement['Resource'])
                    else:
                        user['Permissions']['Deny']['!{}'.format(not_action)] = {'Resources': [], 'Conditions': []}
                        if isinstance(statement['Resource'], list):
                            user['Permissions']['Deny']['!{}'.format(not_action)]['Resources'] = statement['Resource']
                        else:
                            user['Permissions']['Deny']['!{}'.format(not_action)]['Resources'] = [statement['Resource']]
                    if 'Condition' in statement:
                        user['Permissions']['Deny']['!{}'.format(not_action)]['Conditions'].append(statement['Condition'])
                    user['Permissions']['Deny']['!{}'.format(not_action)]['Resources'] = list(set(user['Permissions']['Deny']['!{}'.format(not_action)]['Resources']))  # Remove duplicate resources
            elif 'NotAction' in statement and isinstance(statement['NotAction'], str):
                if '!{}'.format(statement['NotAction']) in user['Permissions']['Deny']:
                    if isinstance(statement['Resource'], list):
                        user['Permissions']['Deny']['!{}'.format(statement['NotAction'])]['Resources'] += statement['Resource']
                    else:
                        user['Permissions']['Deny']['!{}'.format(statement['NotAction'])]['Resources'].append(statement['Resource'])
                else:
                    user['Permissions']['Deny']['!{}'.format(statement['NotAction'])] = {'Resources': [], 'Conditions': []}
                    if isinstance(statement['Resource'], list):
                        user['Permissions']['Deny']['!{}'.format(statement['NotAction'])]['Resources'] = statement['Resource']
                    else:
                        user['Permissions']['Deny']['!{}'.format(statement['NotAction'])]['Resources'] = [statement['Resource']]  # Make sure that resources are always arrays
                if 'Condition' in statement:
                    user['Permissions']['Deny']['!{}'.format(statement['NotAction'])]['Conditions'].append(statement['Condition'])
                user['Permissions']['Deny']['!{}'.format(statement['NotAction'])]['Resources'] = list(set(user['Permissions']['Deny']['!{}'.format(statement['NotAction'])]['Resources']))  # Remove duplicate resources
    return user



if __name__ == '__main__':
    # input AccessKeyId, AccessKeySecret, Region ID, Account ID
    access_key_id = input('  Access Key ID: \n')
    access_key_secret = input('  Secret Access Key: \n')
    region_id = input('  Region ID:\n')
    account_id = input('  Account ID:\n')
    endpoint = f"{account_id}.{region_id}.fc.aliyuncs.com"  # fc endpoint
    client = AcsClient(access_key_id, access_key_secret, region_id)

    roles = []
    marker = None

    # List roles
    request = ListRolesRequest.ListRolesRequest()
    request.set_accept_format('json')
    response = client.do_action_with_exception(request)
    response_json = json.loads(response)

    if 'Roles' in response_json and isinstance(response_json['Roles'], dict):
        if 'Role' in response_json['Roles'] and isinstance(response_json['Roles']['Role'], list):
            for role in response_json['Roles']['Role']:
                if isinstance(role, dict) and 'RoleName' in role:
                    roles.append({'RoleName': role['RoleName'], 'Permissions': {'Allow': {}, 'Deny': {}}})

    print('Enumerating permissions for {} roles...'.format(len(roles)))

    for role in roles:
        role['Policies'] = []
        try:
            attached_policies = []
            try:
                request = ListPoliciesForRoleRequest.ListPoliciesForRoleRequest()
                request.set_RoleName(role['RoleName'])
                response = client.do_action_with_exception(request)
                response_json = json.loads(response.decode('utf-8'))

                policies = response_json.get('Policies', {}).get('Policy', [])
                attached_policies.extend(policies)

                while response_json.get('IsTruncated') == 'true':
                    request.set_Marker(response_json.get('Marker'))
                    response = client.do_action_with_exception(request)
                    response_json = json.loads(response)
                    policies = response_json.get('Policies', {}).get('Policy', [])
                    attached_policies.extend(policies)
                role['Policies'] += attached_policies

            except Exception as e:
                print(f'List attached role policies failed for role {role["RoleName"]}: {e}')

            if 'Policies' in role and role['Policies']:
                for policy in role['Policies']:
                    role = parse_attached_policies(client, [policy], role)

            role.pop('Policies', None)

            print(f'  {role["RoleName"]}... done!')

        except Exception as e:
            print(f'Error, skipping role {role["RoleName"]}: {e}')

    print("Enumeration completed!")

    # Begin privesc scanning
    all_role_permissions = [
        'ram:AttachRolePolicy',
        'ram:CreateRole',
        'ram:PassRole',
        'ram:PutRolePolicy',
        'ram:UpdateAssumeRolePolicy',
        'fc:AddPermission',
        'fc:CreateFunction',
        'fc:UpdateFunctionCode',
        'fc:UpdateFunctionConfiguration',
        'sts:AssumeRole'
    ]

    role_escalation_methods = {
        'ram:AttachRolePolicy': {
            'ram:AttachRolePolicy': True
        },
        'ram:CreateRole': {
            'ram:CreateRole': True
        },
        'ram:PassRole': {
            'ram:PassRole': True
        },
        'ram:PutRolePolicy': {
            'ram:PutRolePolicy': True
        },
        'ram:UpdateAssumeRolePolicy': {
            'ram:UpdateAssumeRolePolicy': True
        },
        'fc:AddPermission': {
            'fc:AddPermission': True
        },
        'fc:CreateFunction': {
            'fc:CreateFunction': True
        },
        'fc:UpdateFunctionCode': {
            'fc:UpdateFunctionCode': True,
        },
        'fc:UpdateFunctionConfiguration': {
            'fc:UpdateFunctionConfiguration': True
        },
        'sts:AssumeRole': {
            'sts:AssumeRole': True
        }
    }

    for role in roles:
        print('\nRole: {}'.format(role['RoleName']))
        checked_perms = {'Allow': {}, 'Deny': {}}
        if 'Permissions' in role and 'Allow' in role['Permissions']:
            # Are they an admin already?
            if '*' in role['Permissions']['Allow'] and role['Permissions']['Allow']['*']['Resources'] == ['*']:
                if role['Permissions']['Deny'] == {} and role['Permissions']['Allow']['*']['Conditions'] == []:
                    role['CheckedMethods'] = {'admin': {}, 'Confirmed': {}, 'Potential': {}}
                    print('  Already an admin!')
                    continue
                else:
                    role['CheckedMethods'] = {'possible_admin': {}, 'Confirmed': {}, 'Potential': {}}
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
                if perm not in checked_perms['Allow']:  # If this permission isn't Allowed, then this method won't work
                    potential = confirmed = False
                    break
                #If this permission is Allowed but resource isn't all, then this method won't work
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
                if perm in checked_perms['Deny'] and perm in checked_perms['Allow']:  # Permission is both Denied and Allowed, leave as potential, not confirmed
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

    fc_client = create_fc_client(access_key_id, access_key_secret, endpoint)
    service_function_role = list_services_and_functions(fc_client)
    #print(service_function_role)
    #add Adding dangerous permissions
    service_function_permissions = update_service_function_role(service_function_role, roles)
    #print(service_function_permissions)
    print_service_function_permissions(service_function_permissions)

    function_escalation_method1 = {
        'sts:AssumeRole': {
            'sts:AssumeRole': True
        },
        'ram:CreateRole+ram:AttachRolePolicy': {
            'ram:CreateRole': True,
            'ram:AttachRolePolicy': True
        },
        'ram:PutRolePolicy': {
            'ram:PutRolePolicy': True
        },
        'ram:UpdateAssumeRolePolicy': {
            'ram:UpdateAssumeRolePolicy': True
        }
    }

    function_escalation_method2 = {
        'ram:PassRole+fc:CreateFunction': {
            'ram:PassRole': True,
            'fc:CreateFunction': True
        },
        'fc:UpdateFunctionCode': {
            'fc:UpdateFunctionCode': True
        }
    }

    # check strategies 1 and 2
    print('\nScan the attack paths in the account.\n')

    all_escalate_privilege = []

    for stack in service_function_permissions:
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
        # print("\nDangerous permissions and their locations in the escalation path:")
        processed_permissions = set()  # track processed permissions
        for method in escalation_group_all:
            permissions = extract_permissions_from_method(method, function_escalation_method1,
                                                          function_escalation_method2)
            for perm in permissions:
                permission_location = []
                if perm not in processed_permissions:  # Only permissions that are not output are processed
                    # print(f"\n  Permission: {perm}")
                    for stack in service_function_permissions:
                        for func in stack['Function']:
                            if perm in func['Confirmed']:
                                # print(f"    Application: {stack['StackName']}, Function: {func['FunctionName']}, RoleArn: {func['RoleArn']}")
                                permission_location.append(
                                    {"Application": stack['StackName'], "Function": func['FunctionName']})
                    processed_permissions.add(perm)
                    all_permission_location.append({"Permission": perm, "location": permission_location})
        # print(all_permission_location)
        print("\nHere are function-based attack paths in the account.\n")

        updated_escalation_group = get_function_based_path(escalation_group_all, all_permission_location)
        for updated_path in updated_escalation_group:
            print(updated_path)

    print("=" * 60)
    print(
        '\nDivide all applications into two groups, combine the resources of the two groups respectively, and detect the attack path.')
    stack_names = [stack['StackName'] for stack in service_function_permissions]
    total_stacks = len(stack_names)
    combinations_list = generate_combinations(stack_names, total_stacks)

    print(
        f"There are {len(combinations_list)} combinations in total. But only the following combination can fulfill the premise of cross-account contamination.")
    # Record the number of valid combinations
    num = 0
    for i, (group1, group2) in enumerate(combinations_list, 1):
        all_permission_location1 = []
        all_permission_location2 = []

        confirmed_group1 = get_confirmed_union(group1, service_function_permissions)
        confirmed_group2 = get_confirmed_union(group2, service_function_permissions)

        # identification of function_escalation_method1 or function_escalation_method2
        escalation_group1 = []
        escalation_group1.extend(check_escalation_method1(confirmed_group1, function_escalation_method1,
                                                          "function_escalation_method1"))
        escalation_group1.extend(
            check_escalation_method2(confirmed_group1, function_escalation_method1, function_escalation_method2,
                                     "function_escalation_method2"))

        escalation_group2 = []
        escalation_group2.extend(check_escalation_method1(confirmed_group2, function_escalation_method1,
                                                          "function_escalation_method1"))
        escalation_group2.extend(
            check_escalation_method2(confirmed_group2, function_escalation_method1, function_escalation_method2,
                                     "function_escalation_method2"))

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
            print("    " + output1)

            print(f"  Confirmed escalated permission: \n    {confirmed_group1}")

            if escalation_group1:
                print("\n  The privilege escalation path in Account 1:")
                for method in escalation_group1:
                    print(f"    {method}")

                # print("\n  Dangerous permissions and their locations in this combination (Account 1):")
                processed_permissions = set()
                for method in escalation_group1:
                    permissions = extract_permissions_from_method(method, function_escalation_method1,
                                                                  function_escalation_method2)
                    for perm in permissions:
                        permission_location1 = []
                        if perm not in processed_permissions:
                            # print(f"\n    Permission: {perm}")
                            for stack in service_function_permissions:
                                if stack['StackName'] in group1:
                                    for func in stack['Function']:
                                        if perm in func['Confirmed']:
                                            # print(f"      Application: {stack['StackName']}, Function: {func['FunctionName']}, RoleArn: {func['RoleArn']}")
                                            permission_location1.append(
                                                {"Application": stack['StackName'], "Function": func['FunctionName']})
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

                # print("\n  Dangerous permissions and their locations in this combination (Account 2):")
                processed_permissions = set()
                for method in escalation_group2:
                    permissions = extract_permissions_from_method(method, function_escalation_method1,
                                                                  function_escalation_method2)
                    for perm in permissions:
                        permission_location2 = []
                        if perm not in processed_permissions:
                            # print(f"\n    Permission: {perm}")
                            for stack in service_function_permissions:
                                if stack['StackName'] in group2:
                                    for func in stack['Function']:
                                        if perm in func['Confirmed']:
                                            # print(f"      Application: {stack['StackName']}, Function: {func['FunctionName']}, RoleArn: {func['RoleArn']}")
                                            permission_location2.append(
                                                {"Application": stack['StackName'], "Function": func['FunctionName']})
                            processed_permissions.add(perm)
                            all_permission_location2.append({"Permission": perm, "location": permission_location2})

                print("\n  Here are function-based attack paths in Account 2.\n")
                updated_escalation_group2 = get_function_based_path(escalation_group2, all_permission_location2)
                for updated_path in updated_escalation_group2:
                    print(updated_path)

            # Check whether account 1 can infect account 2 through the Layer
            if 'fc:UpdateFunctionConfiguration' in confirmed_group2 and escalation_group1:
                print(
                    "\n  Account 2 can be infected by Account 1,because Account 2 have fc:UpdateFunctionConfiguration.")
                # Check whether account 1 can obtain account 2's administrator privileges
                if escalation_group2:
                    print("  Account 1 can obtain Account 2's administrator privileges through the layer.")
                print(f"\n    Permission: fc:UpdateFunctionConfiguration")
                for stack in service_function_permissions:
                    if stack['StackName'] in group2:
                        for func in stack['Function']:
                            if 'fc:UpdateFunctionConfiguration' in func['Confirmed']:
                                print(
                                    f"      Application: {stack['StackName']}, Function: {func['FunctionName']}, RoleArn: {func['RoleArn']}")

    print('\nPrivilege escalation check completed.')