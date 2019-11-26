#
# Copyright 2017 XebiaLabs, Inc.
#
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
#

import time
import sys
import json
import requests
from requests.packages.urllib3.exceptions import SNIMissingWarning, InsecurePlatformWarning, InsecureRequestWarning
import onetimepass as otp


# The variable authorizationHeader has always the same value
authorizationHeader = "ZWRnZWNsaTplZGdlY2xpc2VjcmV0"


def setup_urllib():
    requests.packages.urllib3.disable_warnings(SNIMissingWarning)
    requests.packages.urllib3.disable_warnings(InsecurePlatformWarning)
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

def print_response(response):
    print("Response code: ")
    print(response.status_code)
    print("\n")
    print("Response: ")
    try:
        print response.json()
        print("\n")
    except ValueError:
        print("No JSON returned. \n")
        print(response.content)
        print("\n")

def make_token_six_digits(token):
    if len(str(token)) == 5:
        token = "0%s" % token
    return token


class ApigeeClient(object):

    def __init__(self, apigeeCI):
        self.organizationName = apigeeCI['organizationName']
        self.environmentName = apigeeCI['environmentName']
        self.url = apigeeCI['url']
        self.username = apigeeCI['username']
        self.password = apigeeCI['password']
        self.authentication = (apigeeCI['username'], apigeeCI['password'])
        self.mfa = apigeeCI['mfa']
        self.secretKey = apigeeCI['secretKey']
        self.sso_login_url = "https://login.apigee.com/oauth/token"
        self.proxy_dict = None
        if apigeeCI['httpProxy']:
            httpProxyAddress = apigeeCI['httpProxy'].getProperty('address')
            idx = httpProxyAddress.index(':')
            httpProxyPort = apigeeCI['httpProxy'].getProperty('port')
            self.proxy_dict = {httpProxyAddress[0:idx]: httpProxyAddress + ":" + str(httpProxyPort)}
            print("Http proxy: %s \n" % self.proxy_dict)

    @staticmethod
    def create_apigeeClient(apigeeCI):
        return ApigeeClient(apigeeCI)

    def get_revision_number_of_apiproxy_deployed_to_environment(self, apiProxyName, apiType, environmentName):
        if apiType == "apiproxy":
            resp = self.build_url('/environments/' + environmentName + '/apis/' + apiProxyName + '/deployments')
        elif apiType == "sharedflow":
            resp = self.build_url('/environments/' + environmentName + '/sharedflows/' + apiProxyName + '/deployments')
        else:
            print "Api type %s is not valid. It should be apiproxy or sharedflow. \n" % apiType
            sys.exit(1)
        jsonData = json.loads(resp.text)
        lengthOfNames = len(jsonData['revision'])
        if lengthOfNames > 1:
            print("There are multiple revisions of this %s %s deployed to environment %s \n" % (apiType, apiProxyName, environmentName))
            revisionNumber = jsonData['revision'][lengthOfNames -1]['name']
            print("%s %s revision number %s is the highest revision deployed to environment %s of Apigee organization %s. \n" % (apiType.capitalize(), apiProxyName, revisionNumber, environmentName, self.organizationName))
        else:
            revisionNumber = jsonData['revision'][0]['name']
            print("%s %s revision number %s is deployed to environment %s of Apigee organization %s. \n" % (apiType.capitalize(), apiProxyName, revisionNumber, environmentName, self.organizationName)) 
        return revisionNumber

    def get_description_field_of_apiproxy_revision_number(self, apiProxyName, apiType, revisionNumber):
        if apiType == "apiproxy":
            resp = self.build_url('/apis/' + apiProxyName + '/revisions/' + revisionNumber)
        elif apiType == "sharedflow":
            resp = self.build_url('/sharedflows/' + apiProxyName + '/revisions/' + revisionNumber)
        else:
            print "Api type %s is not valid. It should be apiproxy or sharedflow. \n" % apiType
            sys.exit(1)
        jsonData = json.loads(resp.text)
        descriptionContent = jsonData['description']
        print("%s %s revision number %s has description field content %s. \n" % (apiType.capitalize(), apiProxyName, revisionNumber, descriptionContent))
        return descriptionContent

    def compare_text_field_with_description_field(self, apiProxyName, environmentName, apiType, textField):
        revisionNumber = self.get_revision_number_of_apiproxy_deployed_to_environment(apiProxyName, apiType, environmentName)
        print("Revision number: " + revisionNumber + ".\n")
        descriptionField = self.get_description_field_of_apiproxy_revision_number(apiProxyName, apiType, revisionNumber)
        print("Description field: " + descriptionField + "\n")
        if textField == descriptionField:
            print("Text field %s is equal to description field of deployed application %s. \n" % (textField, descriptionField))
            return descriptionField
        else:
            print "Text field %s is NOT equal to description field of deployed application %s. \n" % (textField, descriptionField)
            sys.exit(1)

    def get_environment_details(self):
        resp = self.build_url('/environments/' + self.environmentName)
        return resp

    def create_one_time_password(self):
        danger_time_interval_in_seconds = 7
        my_secret = self.secretKey
        if my_secret is None:
            raise Exception("Error during creating one time password. The secret key is empty. \n")
        print("Creating the time-based token. \n")
        my_token = otp.get_totp(my_secret)
        my_token = make_token_six_digits(my_token)
        self.token = my_token
        # Let's verify if the token is still valid after some seconds and we are not switching to new interval
        my_token2 = otp.get_totp(my_secret, clock=(int(time.time()) + danger_time_interval_in_seconds))
        my_token2 = make_token_six_digits(my_token2)
        if my_token == my_token2:
            return my_token
        else:
            print("Waiting for the next time interval ...\n")
            time.sleep(danger_time_interval_in_seconds)
            self.token = my_token2
            return my_token2

    def build_authorization_header(self):
        # Check the connection with an http head request. Otherwise, the password is printed when mfa is on.
        resp = requests.head(self.sso_login_url, proxies=self.proxy_dict, verify=False, timeout=60)
        authorization_headers = {}
        if self.mfa:
            my_token = self.create_one_time_password()
            headers = {'Content-Type': 'application/x-www-form-urlencoded;charset=utf-8', 'Accept': 'application/json;charset=utf-8', 'Authorization': 'Basic ' + authorizationHeader}
            params = {'username': self.username, 'password': self.password, 'grant_type': 'password', 'mfa_token': my_token}
            try:
                resp = requests.post(self.sso_login_url, params=params, proxies=self.proxy_dict, verify=False, headers=headers, timeout=60)
                resp.raise_for_status()
            except requests.exceptions.HTTPError:
                print_response(resp)
                raise Exception("Error during creating authorization header.")
            data = resp.json()
            access_token = data['access_token']
            authorization_headers = {'Authorization': 'Bearer ' + access_token}
        return authorization_headers

    def build_org_url(self):
        base_url = self.url
        url = base_url + "/v1/organizations/" + self.organizationName
        return url

    def build_url(self, contextRoot):
        url = self.build_org_url() + contextRoot
        authorization_headers = self.build_authorization_header()
        print("Url: " + url + "\n")
        headers = authorization_headers
        try:
            if self.mfa:
                print("Multi factor authentication is on. \n")
                resp = requests.get(url, proxies=self.proxy_dict, verify=False, headers=headers, timeout=60)
            else:
                print("Multi factor authentication is off \n")
                resp = requests.get(url, auth=self.authentication, proxies=self.proxy_dict, verify=False, headers=headers, timeout=60)
            resp.raise_for_status()
        except requests.exceptions.HTTPError:
            print_response(resp)
            raise Exception("Error during getting deployment details. \n")
        return resp
