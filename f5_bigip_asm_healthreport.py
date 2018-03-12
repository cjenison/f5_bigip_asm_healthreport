#!/usr/bin/python

# Home: https://github.com/cjenison/f5_bigip_asm_healthreport
# Author: Chad Jenison (c.jenison@f5.com)

import argparse
import sys
import requests
import json
import copy
import getpass
from time import sleep

parser = argparse.ArgumentParser(description='A tool to detach ASM policies from virtual to allow some global change to ASM configuration, then restore policies to virtuals')
parser.add_argument('--user', '-u', help='username to use for authentication', required=True)
parser.add_argument('--bigip', '-b', help='IP or hostname of BIG-IP Management or Self IP')

args = parser.parse_args()

def query_yes_no(question, default="no"):
    valid = {"yes": True, "y": True, "ye": True, "no": False, "n": False}
    if default == None:
        prompt = " [y/n] "
    elif default == "yes":
        prompt = " [Y/n] "
    elif default == "no":
        prompt = " [y/N] "
    else:
        raise ValueError("invalid default answer: '%s'" % default)
    while 1:
        sys.stdout.write(question + prompt)
        choice = raw_input().lower()
        if default is not None and choice == '':
            return valid[default]
        elif choice in valid.keys():
            return valid[choice]
        else:
            sys.stdout.write("Please respond with 'yes' or 'no' (or 'y' or 'n').\n")


def get_auth_token(bigip, username, password):
    authbip = requests.session()
    authbip.verify = False
    payload = {}
    payload['username'] = username
    payload['password'] = password
    payload['loginProviderName'] = 'tmos'
    authurl = 'https://%s/mgmt/shared/authn/login' % bigip
    token = authbip.post(authurl, headers=contentJsonHeader, auth=(username, password), data=json.dumps(payload)).json()['token']['token']
    print ('Got Auth Token: %s' % (token))
    return token


passwd = getpass.getpass('Enter Password for: %s: ' % (args.user))
bip = requests.session()
requests.packages.urllib3.disable_warnings()
bip.verify = False
contentJsonHeader = {'Content-Type': "application/json"}
authHeader = {'X-F5-Auth-Token': get_auth_token(args.bigip, args.user, passwd)}
bip.headers.update(authHeader)

ltmVirtualDict = {}
ltmVirtuals = bip.get('https://%s/mgmt/tm/ltm/virtual' % (args.bigip)).json()
for virtual in ltmVirtuals['items']:
    print ('Reading virtual: %s' % (virtual['fullPath']))
    ltmVirtualDict[virtual['fullPath']] = virtual

asmPolicyDict = {}
asmPolicies = bip.get('https://%s/mgmt/tm/asm/policies' % (args.bigip)).json()
for policy in asmPolicies['items']:
    for virtualServer in policy['virtualServers']:
        asmPolicyDict[virtualServer] = policy

ltmVirtualsWithoutAsm = []
for virtual in ltmVirtualDict.keys():
    if asmPolicyDict.get(virtual):
        print('--\nLTM Virtual: %s - FullPath: %s\nDestination: %s' % (ltmVirtualDict[virtual]['name'], virtual, ltmVirtualDict[virtual]['destination'].split("/")[-1]))
        print('ASM Policy Name: %s\nEnforcement Mode: %s' % (asmPolicyDict[virtual]['name'], asmPolicyDict[virtual]['enforcementMode']))
        print('ASM Policy Last Change: %s' % (asmPolicyDict[virtual]['versionDatetime']))
        asmPolicyGeneralSettings = bip.get('https://%s/mgmt/tm/asm/policies/%s/general' % (args.bigip, asmPolicyDict[virtual]['id'])).json()
        if asmPolicyGeneralSettings['trustXff']:
            print('Trust XFF enabled')
            for customXff in asmPolicyGeneralSettings.get('customXffHeaders'):
                print('Custom XFF Header: %s' % (customXff))
        else:
            print('Trust XFF disabled')
        if ltmVirtualDict[virtual].get('securityLogProfiles'):
            for logProfile in ltmVirtualDict[virtual]['securityLogProfiles']:
                print('Log Profile: %s' % (logProfile))
        else:
            print('Log Profile Not Attached')
    else:
        ltmVirtualsWithoutAsm.append(virtual)

if ltmVirtualsWithoutAsm:
    print ('--\nLTM Virtuals Without an ASM Policy')
for virtual in ltmVirtualsWithoutAsm:
    print virtual

#if query_yes_no('Ready to Proceed with restoration of ASM Policy to Virtuals?', default="no"):
#    pass
