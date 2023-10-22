import requests
import json
import boto3
from bs4 import BeautifulSoup

# composePolicy, decomposePolicy, checkMultiMFAStatus, createX509, cuid, generateKeyPairs
methods = { "services"                    : lambda p: None,
            "actions"                     : lambda p: { "serviceName": p, "RegionName": "eu-central-1" },
            "resources"                   : lambda p: None,
            "contextKeys"                 : lambda p: None,
            "globalConditionKeys"         : lambda p: None,
            "getServiceLinkedRoleTemplate": lambda p: { "serviceName": p },
            "policySummary"               : lambda p: { "policyDocument": p },
            "validate"                    : lambda p: { "policy": json.dumps(p), "type": "" } }

class ConsoleSession:
    def __init__(self, boto3_session):
        self._credentials = boto3_session.get_credentials()
        self._signed_in = False
        self._csrf_token = None
        self._cache = {method: {} for method in methods}
        self._rsession = requests.Session()

    def __getattribute__(self, name):
        if name in methods:
            def make_lambda(method, converter):
                return lambda param=None: self.get_api_result(method, converter(param))
            return make_lambda(name, methods[name])
        else:
            return object.__getattribute__(self, name)

    def signin(self):
        token = json.loads(self._rsession.get(
            "https://signin.aws.amazon.com/federation", 
            params={
                "Action": "getSigninToken",
                "Session": json.dumps({
                    "sessionId": self._credentials.access_key,
                    "sessionKey": self._credentials.secret_key,
                    "sessionToken": self._credentials.token
                })
            }
        ).text)["SigninToken"]
        self._rsession.get(
            "https://signin.aws.amazon.com/federation",
            params={
                "Action": "login",
                "Issuer": None,
                "Destination": "https://console.aws.amazon.com/",
                "SigninToken": token
            }
        )
        for m in BeautifulSoup(self._rsession.get(
            "https://us-east-1.console.aws.amazon.com/iamv2/home#",
            params={ "region": "eu-central-1", "state": "hashArgs" }
        ).text, "html.parser").find_all("meta"):
            if m.get("name") == "awsc-csrf-token":
                self._csrf_token = m["content"]
        self._signed_in = True

    def get_api_result(self, path, param=None):
        not self._signed_in and self.signin()
        params = json.dumps(param)
        if self._cache[path].get(params, None):
            return self._cache[path][params]
        self._cache[path][params] = json.loads(self._rsession.post(
            "https://us-east-1.console.aws.amazon.com/iamv2/api/iamv2",
            headers={
                "Content-Type": "application/json",
                "X-CSRF-Token": self._csrf_token,
            },
            data=json.dumps({
                "headers": { "Content-Type": "application/json" },
                "path": f"/prod/{path}",
                "method": "POST",
                "region": "us-east-1",
                "params": {},
                **({ "contentString": params } if params else {})
            })
        ).text)
        return self._cache[path][params]
