# aws-iamv2

Access iam metadata on services, their IAM actions, resources and condition keys

# Create a session (simple)

```python
    boto_session = boto3.Session(region_name='us-east-1')
    console_session = ConsoleSession(boto_session)
```

# Create a session assuming a role

Assuming a role you can minimizing the AWS access. Replace YOUR_ACCOUNT and YOUR_ROLE in the code below.

```python
    creds = boto3.Session(region_name='us-east-1').client('sts').assume_role(
        RoleArn='arn:aws:iam::%%%YOUR_ACCOUNT%%%:role/%%%YOUR_ROLE%%%',
        RoleSessionName='my_session',
        Policy=json.dumps({ 
            "Version": "2012-10-17", 
            "Statement": [{
                "Effect": "Deny",
                "Action": "*",
                "Resource": "*"
            }]
        })
    )["Credentials"]
    boto_session = boto3.Session(
        aws_access_key_id=creds['AccessKeyId'],
        aws_secret_access_key=creds['SecretAccessKey'],
        aws_session_token=creds['SessionToken']
    )

    console_session = ConsoleSession(boto_session)
```

After you have a session you can start calling APIs

# Retrieve services and action

```python
    services = console_session.services()
    for service in services[0:10]:
        actions = console_session.actions(service["serviceKeyName"])
        print(service["serviceKeyName"], len(actions))
```

# Get the contextKeys and globalConditionKeys

```python
    context_keys = console_session.contextKeys()
    print('contextKeys:', len(context_keys))
    global_condition_keys = console_session.globalConditionKeys()
    print('globalConditionKeys:', len(global_condition_keys))
```

# Use getServiceLinkedRoleTemplate to get a template

```python
    template = console_session.getServiceLinkedRoleTemplate('autoscaling.amazonaws.com')
    print(json.dumps(console_session.policySummary(template["namedPermissionsPolicies"][0]["policyDocument"]), indent=2))
```

# Validate a policy

```python
    print(json.dumps(console_session.validate({ 
        "Version": "2012-10-17", 
        "Statement": [{
            "Sid": "AllowViewAccountInfo",
            "Effect": "Allow",
            "Action": [
                "iam:GetAccountPasswordPolicy",
                "iam:ListVirtualMFADevices"
            ],
            "Resource": "*"
        }]
    })))
```
