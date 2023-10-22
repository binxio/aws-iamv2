import boto3
from iamv2 import ConsoleSession
import re

awssvcs = {}
console_session = None

def get_iam_info():
    global console_session
    boto_session = boto3.Session(region_name='us-east-1')
    console_session = ConsoleSession(boto_session)

    services = console_session.services()
    for service in services:
        name = service["serviceName"]
        if name not in awssvcs:
            awssvcs[name] = { "parts": [] }
        awssvcs[name]["parts"].append(service)

policy = {
    "Version": "2012-10-17", 
    "Statement": [{ 
        "Effect": "Deny", 
        "NotAction": "cloudtrail:De*", 
        "Resource": "*"
    }]
}

def get_statement_actions(statement):
    result = []
    actions = statement.get("Action") or statement.get("NotAction")
    reverse = "NotAction" in statement
    reverse = not reverse if statement["Effect"] == "Deny" else reverse
    actions = [actions] if isinstance(actions, str) else actions
    for action in actions:
        service, act = action.split(':')
        if "Actions" not in awssvcs[service]:
            awssvcs[service]["Actions"] = console_session.actions(awssvcs[service]["parts"][0]["serviceKeyName"])
        actrgx = act.replace('*', '[A-Za-z]+')
        for svc_action in awssvcs[service]["Actions"]:
            if bool(re.match(actrgx, svc_action["actionName"], flags=re.IGNORECASE)) ^ reverse:
                result.append(svc_action)
    return result

def get_policy_actions(policy):
    for statement in policy["Statement"]:
        yield get_statement_actions(statement)

if __name__ == "__main__":
    get_iam_info()
    for statement_actions in get_policy_actions(policy):
        statement_actions = sorted(statement_actions, key=lambda x: x["actionName"])
        for action in statement_actions:
            print(f'{action["actionName"]:40} {", ".join(action["actionGroups"])}')

