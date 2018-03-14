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
passwdoption = parser.add_mutually_exclusive_group()
passwdoption.add_argument('--password', '-p', help='Supply Password as command line argument \(dangerous due to shell history\)')
passwdoption.add_argument('--passfile', '-pf', help='Obtain password from a text file \(with password string as the only contents of file\)')
parser.add_argument('--hostport', '-hp', help='List of NameIP:port pairs that will be checked with nc \(Example: logserver,514\) for reachability', nargs='*')

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

def get_confirmed_password(bigip, username, password):
    bip = requests.session()
    bip.verify = False
    bip.auth = (username, password)
    credentialsValidated = False
    while not credentialsValidated:
        testRequest = bip.get('https://%s/mgmt/tm/sys/' % (bigip))
        if testRequest.status_code == 200:
            credentialsValidated = True
            return password
        elif testRequest.status_code == 401:
            print ('Invalid credentials for user %s' % (user))
            passwordRetryQuery = 'Retry with new password (No to exit)?'
            if query_yes_no(passwordRetryQuery, default="yes"):
                password = getpass.getpass('Re-enter Password for %s' % (user))
                bip.auth = (username, password)
            else:
                print('Exiting due to invalid authentication credentials')
                quit()
        else:
            print('Unexpected Error from test request to validate credentials')
            print('Status Code: %s' % (testRequest.status_code))
            print('Body: %s' % (testRequest.content))
            print('Exiting due to unexpected error condition')
            quit()

def get_system_info(bigip, username, password):
    systemInfo = dict()
    bip = requests.session()
    bip.verify = False
    bip.auth = (username, password)
    #bip.headers.update(authHeader)
    globalSettings = bip.get('https://%s/mgmt/tm/sys/global-settings/' % (bigip)).json()
    hardware = bip.get('https://%s/mgmt/tm/sys/hardware/' % (bigip)).json()
    partitions = list()
    partitionCollection = bip.get('https://%s/mgmt/tm/auth/partition/' % (bigip)).json()
    for partition in partitionCollection['items']:
        partitions.append(partition['fullPath'])
    provisionedModules = list()
    provision = bip.get('https://%s/mgmt/tm/sys/provision/' % (bigip)).json()
    for module in provision['items']:
        if module.get('level'):
            if module['level'] != 'none':
                provisionedModules.append(module['name'])
    print ('Provisioned Modules: %s' % (provisionedModules))
    systemInfo['provisionedModules'] = provisionedModules
    systemInfo['baseMac'] = hardware['entries']['https://localhost/mgmt/tm/sys/hardware/platform']['nestedStats']['entries']['https://localhost/mgmt/tm/sys/hardware/platform/0']['nestedStats']['entries']['baseMac']['description']
    systemInfo['marketingName'] = hardware['entries']['https://localhost/mgmt/tm/sys/hardware/platform']['nestedStats']['entries']['https://localhost/mgmt/tm/sys/hardware/platform/0']['nestedStats']['entries']['marketingName']['description']
    version = bip.get('https://%s/mgmt/tm/sys/version/' % (bigip)).json()
    if version.get('nestedStats'):
        systemInfo['version'] = version['entries']['https://localhost/mgmt/tm/sys/version/0']['nestedStats']['entries']['Version']['description']
    else:
        volumes = bip.get('https://%s/mgmt/tm/sys/software/volume' % (bigip)).json()
        for volume in volumes['items']:
            if volume.get('active'):
                if volume['active'] == True:
                    systemInfo['version'] = volume['version']
    systemInfo['shortVersion'] = float('%s.%s' % (systemInfo['version'].split(".")[0], systemInfo['version'].split(".")[1]))
    systemDatePayload = {'command':'run', 'utilCmdArgs': '-c \'date +%Y%m%d\''}
    systemInfo['systemDate'] = bip.post('https://%s/mgmt/tm/util/bash' % (args.bigip), headers=contentJsonHeader, data=json.dumps(systemDatePayload)).json()['commandResult']
    print ('System Date: %s' % (systemInfo['systemDate']))
    systemInfo['hostname'] = globalSettings['hostname']
    systemInfo['provision'] = provision
    print ('hostname: %s' % (systemInfo['hostname']))
    print ('version: %s' % (systemInfo['version']))
    systemInfo['provision'] = bip.get('https://%s/mgmt/tm/sys/provision/' % (bigip)).json()
    return systemInfo

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


requests.packages.urllib3.disable_warnings()
if args.password:
    unverifiedPassword = args.password
elif args.passfile:
    with open(args.passfile, 'r') as file:
        unverifiedPassword = file.read().strip()
else:
   unverifiedPassword = getpass.getpass('Enter Password for: %s: ' % (args.user))

password = get_confirmed_password(args.bigip, args.user, unverifiedPassword)
bip = requests.session()
bip.verify = False
contentJsonHeader = {'Content-Type': "application/json"}
bipSystemInfo = get_system_info(args.bigip, args.user, password)
if float('%s.%s' % (bipSystemInfo['version'].split(".")[0], bipSystemInfo['version'][1])) >= 11.6:
    authHeader = {'X-F5-Auth-Token': get_auth_token(args.bigip, args.user, password)}
    bip.headers.update(authHeader)
else:
    bip.auth = (args.user, password)

ltmVirtualDict = {}
ltmVirtuals = bip.get('https://%s/mgmt/tm/ltm/virtual' % (args.bigip)).json()
for virtual in ltmVirtuals['items']:
    print ('Reading virtual: %s' % (virtual['fullPath']))
    ltmVirtualDict[virtual['fullPath']] = virtual

if 'asm' in bipSystemInfo['provisionedModules']:
    asmPolicyDict = {}
    asmPolicies = bip.get('https://%s/mgmt/tm/asm/policies' % (args.bigip)).json()
    for policy in asmPolicies['items']:
        for virtualServer in policy['virtualServers']:
            asmPolicyDict[virtualServer] = policy
else:
    print ('ASM Module Not Provisioned')

ltmVirtualsWithoutAsm = []
for virtual in ltmVirtualDict.keys():
    if asmPolicyDict.get(virtual):
        print('--\nLTM Virtual: %s - FullPath: %s\nDestination: %s' % (ltmVirtualDict[virtual]['name'], virtual, ltmVirtualDict[virtual]['destination'].split("/")[-1]))
        print('ASM Policy Name: %s\nEnforcement Mode: %s' % (asmPolicyDict[virtual]['name'], asmPolicyDict[virtual]['enforcementMode']))
        print('ASM Policy Last Change: %s' % (asmPolicyDict[virtual]['versionDatetime']))
        if bipSystemInfo['shortVersion'] >= 12.0:
            pass
        else:
            policyBuilderSettings = bip.get('https://%s/mgmt/tm/asm/policies/%s/policy-builder/' % (args.bigip, asmPolicyDict[virtual]['id'])).json()
            if policyBuilderSettings['enablePolicyBuilder']:
                print ('Policy Builder Enabled')
            else:
                print ('Policy Builder Disabled')
        asmPolicyGeneralSettings = bip.get('https://%s/mgmt/tm/asm/policies/%s/general' % (args.bigip, asmPolicyDict[virtual]['id'])).json()
        print ('asmPolicyGeneralSettings: %s' % (json.dumps(asmPolicyGeneralSettings)))
        if asmPolicyGeneralSettings.get('code') != 501:
            if asmPolicyGeneralSettings['trustXff']:
                print('Trust XFF enabled')
                for customXff in asmPolicyGeneralSettings.get('customXffHeaders'):
                    print('Custom XFF Header: %s' % (customXff))
            else:
                print('Trust XFF disabled')
        else:
            if asmPolicyDict[virtual]['trustXff']:
                print('Trust XFF enabled')
                for customXff in asmPolicyDict.get('customXffHeaders'):
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

### BOX GLOBAL HEALTH CHECK
licenseCheckPayload = {'command':'run', 'utilCmdArgs': '-c \'grep trust /config/bigip.license\''}
licenseCheck = bip.post('https://%s/mgmt/tm/util/bash' % (args.bigip), headers=contentJsonHeader, data=json.dumps(licenseCheckPayload)).json()
ipIntelligenceLicensed = False
if licenseCheck['commandResult'] != '':
    ipIntelEnd = licenseCheck['commandResult'].split('_')[0]
    if int(bipSystemInfo['systemDate']) > int(ipIntelEnd):
        print ('IP Intelligence License Appears to be Expired - End Date: %s - System Date: %s' % (ipIntelEnd, bipSystemInfo['systemDate']))
    else:
        print ('IP Intelligence License Appears Valid - End Date: %s - System Date: %s' % (ipIntelEnd, bipSystemInfo['systemDate']))
        ipIntelligenceLicensed = True
if ipIntelligenceLicensed:
    print ('IP Intelligence Licensed - End: %s' % (ipIntelEnd))
    checkBrightCloudPayload = {'command': 'run', 'utilCmdArgs': '-c \'nc -z -w3 vector.brightcloud.com 443\''}
    checkBrightCloud = bip.post('https://%s/mgmt/tm/util/bash' % (args.bigip), headers=contentJsonHeader, data=json.dumps(checkBrightCloudPayload)).json()
    if 'getaddrinfo' in checkBrightCloud['commandResult'] or 'name resolution' in checkBrightCloud['commandResult']:
        print ('Unsuccessful attempt to reach Brightcloud due to name resolution problem')
    elif 'succeeded' in checkBrightCloud['commandResult']:
        print ('Successfully Reached Brightcloud')
    elif checkBrightCloud['commandResult'] == '':
        print ('Unsuccessful Attempt to Reach Brightcloud')
    else:
        print ('Unknown Error in reaching Brightcloud: %s' % (checkBrightCloud['commandResult']))
else:
    print ('BIG-IP IP Intelligence not licensed')

if args.hostport:
    for hostPort in args.hostport:
        print ('Checking Host: %s Port: %s for reachability' % (hostPort.split(',')[0], hostPort.split(',')[1]))
        checkHostPayload = {'command': 'run', 'utilCmdArgs': '-c \'nc -z -w3 %s %s\'' % (hostPort.split(',')[0], hostPort.split(',')[1])}
        checkHost = bip.post('https://%s/mgmt/tm/util/bash' % (args.bigip), headers=contentJsonHeader, data=json.dumps(checkHostPayload)).json()
        if 'getaddrinfo' in checkHost['commandResult']:
            print ('Unsuccessful attempt to reach: %s %s due to name resolution problem' % (hostPort.split(',')[0], hostPort.split(',')[1]))
        elif 'succeeded' in checkHost['commandResult']:
            print ('Successfully Reached Host: %s %s' % (hostPort.split(',')[0], hostPort.split(',')[1]))
        elif checkHost['commandResult'] == '':
            print ('Unsuccessful Attempt to Reach Host: %s %s' % (hostPort.split(',')[0], hostPort.split(',')[1]))
        else:
            print ('Unknown Error in reaching %s %s: %s' % (hostPort.split(',')[0], hostPort.split(',')[1], checkBrightCloud['commandResult']))
#if query_yes_no('Ready to Proceed with restoration of ASM Policy to Virtuals?', default="no"):
#    pass
