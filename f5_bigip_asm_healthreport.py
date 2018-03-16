#!/usr/bin/python

# Home: https://github.com/cjenison/f5_bigip_asm_healthreport
# Author: Chad Jenison (c.jenison@f5.com)

import argparse
import sys
import requests
import json
import copy
import getpass
import re
from time import sleep

parser = argparse.ArgumentParser(description='A tool to give summary/health data on one or more BIG-IP ASM systems')
parser.add_argument('--user', '-u', help='username to use for authentication', required=True)
mode = parser.add_mutually_exclusive_group()
mode.add_argument('--bigip', '-b', help='IP or hostname of BIG-IP Management or Self IP')
mode.add_argument('--systemlistfile', '-s', help='Input file containing IP\'s or hostnames of BIG-IP systems \(Format: pairName: ipOrHostname1, ipOrHostname2\)')
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
            if args.password or args.passfile:
                print ('Invalid credentials passed via command line argument or as file content; Exiting...')
                quit()
            else:
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
    systemInfo['ipOrHostname'] = bigip
    systemInfo['user'] = username
    systemInfo['pass'] = get_confirmed_password(bigip, username, password)
    unknownbip = requests.session()
    unknownbip.verify = False
    unknownbip.auth = (username, systemInfo['pass'])
    version = unknownbip.get('https://%s/mgmt/tm/sys/version/' % (bigip)).json()
    bip = requests.session()
    bip.verify = False
    if version.get('nestedStats'):
        systemInfo['version'] = version['entries']['https://localhost/mgmt/tm/sys/version/0']['nestedStats']['entries']['Version']['description']
    else:
        volumes = unknownbip.get('https://%s/mgmt/tm/sys/software/volume' % (bigip)).json()
        for volume in volumes['items']:
            if volume.get('active'):
                if volume['active'] == True:
                    systemInfo['version'] = volume['version']
    systemInfo['shortVersion'] = float('%s.%s' % (systemInfo['version'].split('.')[0], systemInfo['version'].split('.')[1]))
    if systemInfo['shortVersion'] >= 11.6:
        systemInfo['authToken'] = get_auth_token(bigip, systemInfo['user'], systemInfo['pass'])
        systemInfo['authHeader'] = {'X-F5-Auth-Token': systemInfo['authToken']}
        bip.headers.update(systemInfo['authHeader'])
    else:
        bip.auth = (systemInfo['user'], systemInfo['pass'])
        systemInfo['authToken'] = None
        systemInfo['authHeader'] = None
    #bip.headers.update(authHeader)
    globalSettings = bip.get('https://%s/mgmt/tm/sys/global-settings/' % (bigip)).json()
    hardware = bip.get('https://%s/mgmt/tm/sys/hardware/' % (bigip)).json()
    partitions = list()
    partitionCollection = bip.get('https://%s/mgmt/tm/auth/partition/' % (bigip)).json()
    for partition in partitionCollection['items']:
        partitions.append(partition['fullPath'])
    provision = bip.get('https://%s/mgmt/tm/sys/provision/' % (bigip)).json()
    systemInfo['provision'] = provision
    provisionedModules = list()
    for module in provision['items']:
        if module.get('level'):
            if module['level'] != 'none':
                provisionedModules.append(module['name'])
    print ('Provisioned Modules: %s' % (json.dumps(provisionedModules)))
    systemInfo['provisionedModules'] = provisionedModules
    systemInfo['baseMac'] = hardware['entries']['https://localhost/mgmt/tm/sys/hardware/platform']['nestedStats']['entries']['https://localhost/mgmt/tm/sys/hardware/platform/0']['nestedStats']['entries']['baseMac']['description']
    systemInfo['marketingName'] = hardware['entries']['https://localhost/mgmt/tm/sys/hardware/platform']['nestedStats']['entries']['https://localhost/mgmt/tm/sys/hardware/platform/0']['nestedStats']['entries']['marketingName']['description']
    systemDatePayload = {'command':'run', 'utilCmdArgs': '-c \'date +%Y%m%d\''}
    systemInfo['systemDate'] = bip.post('https://%s/mgmt/tm/util/bash' % (bigip), headers=contentJsonHeader, data=json.dumps(systemDatePayload)).json()['commandResult'].strip()
    syncStatusPayload = {'command':'run', 'utilCmdArgs': '-c \'tmsh show cm sync-status\''}
    systemInfo['syncStatus'] = bip.post('https://%s/mgmt/tm/util/bash' % (bigip), headers=contentJsonHeader, data=json.dumps(syncStatusPayload)).json()['commandResult']
    syncStatusRegex = re.search('Color\s+(\S+)', systemInfo['syncStatus'])
    systemInfo['syncStatusColor'] = syncStatusRegex.group(0)
    systemInfo['hostname'] = globalSettings['hostname']
    devices = bip.get('https://%s/mgmt/tm/cm/device' % (bigip)).json()
    for device in devices['items']:
        if device['selfDevice'] == 'true':
            systemInfo['failoverState'] = device['failoverState']
            systemInfo['unicastAddresses'] = device['unicastAddress']
            systemInfo['configsyncIp'] = device['configsyncIp']
            systemInfo['timeLimitedModules'] = device['timeLimitedModules']
    return systemInfo

### BOX GLOBAL HEALTH CHECK
def bigip_asm_device_check(bigip):
    bip = requests.session()
    bip.verify = False
    if bigip['authHeader']:
        bip.headers.update(bigip['authHeader'])
    else:
        bip.auth = (bigip['user'], bigip['pass'])
    if bigip['syncStatusColor'] != 'green':
        print ('System Out of Sync with Peer - Status:')
        print bigip['syncStatus']
    else:
        print ('System In Sync with Peer')
    licenseCheckPayload = {'command':'run', 'utilCmdArgs': '-c \'grep trust /config/bigip.license\''}
    licenseCheck = bip.post('https://%s/mgmt/tm/util/bash' % (bigip['ipOrHostname']), headers=contentJsonHeader, data=json.dumps(licenseCheckPayload)).json()
    ipIntelligenceLicensed = False
    if licenseCheck['commandResult'] != '':
        ipIntelEnd = licenseCheck['commandResult'].split('_')[0]
        if int(bigip['systemDate']) > int(ipIntelEnd):
            print ('IP Intelligence License Appears to be Expired - End Date: %s - System Date: %s' % (ipIntelEnd, bigip['systemDate']))
        else:
            print ('IP Intelligence License Appears Valid - End Date: %s - System Date: %s' % (ipIntelEnd, bigip['systemDate']))
            ipIntelligenceLicensed = True
            if int(bigip['systemDate']) + 14 > int(ipIntelEnd):
                print ('IP Intelligence Licensed Expiring within 14 days')
    if ipIntelligenceLicensed:
        checkBrightCloudPayload = {'command': 'run', 'utilCmdArgs': '-c \'nc -z -w3 vector.brightcloud.com 443\''}
        checkBrightCloud = bip.post('https://%s/mgmt/tm/util/bash' % (bigip['ipOrHostname']), headers=contentJsonHeader, data=json.dumps(checkBrightCloudPayload)).json()
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
            checkHost = bip.post('https://%s/mgmt/tm/util/bash' % (bigip['ipOrHostname']), headers=contentJsonHeader, data=json.dumps(checkHostPayload)).json()
            if 'getaddrinfo' in checkHost['commandResult']:
                print ('Unsuccessful attempt to reach: %s %s due to name resolution problem' % (hostPort.split(',')[0], hostPort.split(',')[1]))
            elif 'succeeded' in checkHost['commandResult']:
                print ('Successfully Reached Host: %s %s' % (hostPort.split(',')[0], hostPort.split(',')[1]))
            elif checkHost['commandResult'] == '':
                print ('Unsuccessful Attempt to Reach Host: %s %s' % (hostPort.split(',')[0], hostPort.split(',')[1]))
            else:
                print ('Unknown Error in reaching %s %s: %s' % (hostPort.split(',')[0], hostPort.split(',')[1], checkBrightCloud['commandResult']))

def bigip_asm_virtual_report(bigip):
    bip = requests.session()
    bip.verify = False
    if bigip['authHeader']:
        bip.headers.update(bigip['authHeader'])
    else:
        bip.auth = (bigip['user'], bigip['pass'])
    ltmVirtualDict = {}
    ltmVirtuals = bip.get('https://%s/mgmt/tm/ltm/virtual' % (bigip['ipOrHostname'])).json()
    for virtual in ltmVirtuals['items']:
        print ('Reading virtual: %s' % (virtual['fullPath']))
        ltmVirtualDict[virtual['fullPath']] = virtual

    if 'asm' in bigip['provisionedModules']:
        asmPolicyDict = {}
        asmPolicies = bip.get('https://%s/mgmt/tm/asm/policies' % (bigip['ipOrHostname'])).json()
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
            if bigip['shortVersion'] >= 12.0:
                pass
            else:
                policyBuilderSettings = bip.get('https://%s/mgmt/tm/asm/policies/%s/policy-builder/' % (bigip['ipOrHostname'], asmPolicyDict[virtual]['id'])).json()
                if policyBuilderSettings['enablePolicyBuilder']:
                    print ('Policy Builder Enabled')
                else:
                    print ('Policy Builder Disabled')
            asmPolicyGeneralSettings = bip.get('https://%s/mgmt/tm/asm/policies/%s/general' % (bigip['ipOrHostname'], asmPolicyDict[virtual]['id'])).json()
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
            violationsBlocking = bip.get('https://%s/mgmt/tm/asm/policies/%s/blocking-settings/violations/' % (bigip['ipOrHostname'], asmPolicyDict[virtual]['id'])).json()
            for violation in violationsBlocking['items']:
                if violation['description'] == 'Access from malicious IP address':
                    if violation['block']:
                        print ('Access from malicious IP Address - Blocking Enabled')
                    else:
                        print ('Access from malicious IP Address - Blocking Disabled')
                    if violation['alarm']:
                        print ('Access from malicious IP Address - Alarm Enabled')
                    else:
                        print ('Access from malicious IP Address - Alarm Disabled')

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

def get_auth_token(bigip, username, password):
    authbip = requests.session()
    authbip.verify = False
    payload = {}
    payload['username'] = username
    payload['password'] = password
    payload['loginProviderName'] = 'tmos'
    authurl = 'https://%s/mgmt/shared/authn/login' % (bigip)
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

contentJsonHeader = {'Content-Type': "application/json"}

if args.bigip:
    singleBigip = get_system_info(args.bigip, args.user, unverifiedPassword)
    bigip_asm_device_check(singleBigip)
    bigip_asm_virtual_report(singleBigip)
else:
    with open(args.systemlistfile, 'r') as systems:
        for line in systems:
            pairName = line.split(':')[0]
            bigipAaddr = line.split(':')[1].split(',')[0].strip()
            bigipBaddr = line.split(':')[1].split(',')[1].strip()
            bigipA = get_system_info(bigipAaddr, args.user, unverifiedPassword)
            bigipB = get_system_info(bigipBaddr, args.user, unverifiedPassword)
            if bigipA['failoverState'] == 'active':
                activeBigip = bigipA
            else:
                standbyBigip = bigipA
            if bigipB['failoverState'] == 'active':
                activeBigip = bigipB
            else:
                standbyBigip = bigipB
            print ('Pair Name: %s - Active BIG-IP: %s - Standby BIG-IP: %s' % (pairName, activeBigip['hostname'], standbyBigip['hostname']))
            print ('--Active System Info--')
            bigip_asm_device_check(activeBigip)
            print ('--Standby System Info--')
            bigip_asm_device_check(standbyBigip)
            print ('--Active Virtual(s) Report--')
            bigip_asm_virtual_report(activeBigip)




#if query_yes_no('Ready to Proceed with restoration of ASM Policy to Virtuals?', default="no"):
#    pass
