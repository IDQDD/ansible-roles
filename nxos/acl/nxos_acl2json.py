#!/usr/bin/env python
# transform NXOS ACL into JSON and convert it to a dynamic inventory blob for a use with ansible
'''
# ACL sample
10 deny udp any ra 1920 200 any ra 300 400 log
20 permit udp any ra 111 222 any eq 333
no 25
30 permit tcp any eq 303 any ra 300 400 log
40 permit udp any any eq ntp log
45 permit tcp 192.1.60.0/24 eq 19224 10.1.2.111/32 log
51 permit tcp 192.1.60.0/24 192.1.2.231/32
80 deny ip any any log

#json sample
{
    "n9k": {
        "hosts": ["n9k1", "n9k2"],
        "vars": {
            acl: {
                "aclname1": [
                    {"src": "any", "seq": "10", "dest": "any", "proto": "udp", "state": "present"},
                    {"state": "absent", "seq": "35"}
                ],
                "aclname2": [
                    {"src": "any", "log": "enable", "seq": "192", "dest": "any", "proto": "tcp", "state": "present"}
                ]
            }
        }
    }
}


{
    "n9k": {
        "hosts": ["n9k1", "n9k2"],
        "vars": {
            acl: [
                    {
                        "aclname": "name1,
                        "ace": [{"src": "any", "seq": "10", "dest": "any", "proto": "udp", "state": "present"}, {"state": "absent", "seq": "35"}]
                    },
                    {
                        "aclname": "name2",
                        "ace": [{"src": "any", "log": "enable", "seq": "192", "dest": "any", "proto": "tcp", "state": "present"}]
                    }
                ]
            }
        }
    }
}
'''

import json
import ipaddress
import os.path
import sys
import argparse
from glob import glob
from ansible import errors


acl_skel=[
    "seq",              #0
    "action",           #1
    "proto",            #2
    "src",              #3
    "src_port_op",      #4
    "src_port1",        #5
    "src_port2",        #6
    "dest",             #7
    "dest_port_op",     #8
    "dest_port1",       #9
    "dest_port2",        #10
    "log"               #11
]

def isValidPrefix(val):
    try:
        if val == "any" or (ipaddress.ip_network(unicode(val)) and "/" in val):
            return val
        else:
            print "IP network address '%s' has to have a prefix" % val
            exit(1)
    except ValueError, e:
        raise errors.AnsibleFilterError('normalize_interface plugin error: {0}'.format(str(e)))


def ParseACL(data):

    rlist = list()

    for ace in data.splitlines():
        dtmp=dict()
        dtmp["state"] = "present"
        acelist = ace.split()

    # check if ace should be deleted 'no'
        if acelist[0] ==  "no":
            if acelist[1].isdigit():
                dtmp['seq'] = acelist[1]
                dtmp['state'] = 'absent'
                rlist.append(dtmp)
                continue
            else:
                print "incorrect sequense number of ACE: {0}".format(str(acelist[1]))
                exit(1)

    # first 4 fields are predetermined so we just need to validate them
        if acelist[0].isdigit():
            dtmp['seq'] = acelist[0]
        else:
            print "incorrect sequense number of ACE: {0}".format(str(acelist[1]))
            exit(1)

        if acelist[1] in ('permit', 'deny'):
            dtmp[acl_skel[1]] = acelist[1]
        elif acelist[1] == "remark":
            dtmp[acl_skel[1]] = acelist[1]
            dtmp["remark"] = " ".join(acelist[2:])
            rlist.append(dtmp)
            continue
        else:
            print "action can be 'permit', 'deny" or "remark"
            exit(1)

        if acelist[2] in ('ip', 'tcp', 'udp', 'icmp', 'gre', 'ah', 'esp'):
            dtmp[acl_skel[2]] = acelist[2]
        else:
            print "unknown protocol: {0}".format(str(acelist[2]))
            exit(1)

        if isValidPrefix(acelist[3]):
            dtmp[acl_skel[3]] = acelist[3]

    # lookup and validate the remaining (don't even try to understand. It's magic here)
        i, k = 4, 0
        while i< len(acelist):
            val = acelist[i]

            if val == "log":  # if log(11)
                dtmp["log"] = 'enable'
                break  # break while loop

            elif val in ("eq", "gt", "lt", "noq"):
                dtmp[acl_skel[i + k]] = val  # dst_port_op(8)
                dtmp[acl_skel[i + k + 1]] = acelist[i + 1]  # dst_port1(9)
                i += 1
                k += 1

            elif val.startswith("ra"):
                dtmp[acl_skel[i + k]] = "range"
                dtmp[acl_skel[i + k + 1]] = acelist[i + 1]  # dst_port2(10)
                dtmp[acl_skel[i + k + 2]] = acelist[i + 2]
                i += 2

            else:
                if i == 4: k = 3  # skip src ports
                dtmp[acl_skel[i + k]] = isValidPrefix(val)



            i += 1  # iterate over acelist

        #print json.dumps(dtmp, indent=4, sort_keys=True)
        rlist.append(dtmp)

    return rlist

def get_inventory():

    fileglob = glob('./acl/*.acl')
    inventory = {}
    group = {}
    acldict = {}
    acllist = []

    for filename in fileglob:
        aclname = os.path.splitext(os.path.basename(filename))[0]
        acedict=dict()

        with open(filename, 'r') as f:
            data = f.read()

            acedict["ace"] = ParseACL(data)
            acedict["aclname"] = aclname

        f.close()
        acllist.append(acedict)

    acldict["acl"] = acllist
    group['vars'] = acldict
    group["hosts"] = ['n9k1', 'n9k2']
    inventory['n9k'] = group
    #print json.dumps(inventory, indent=4, sort_keys=True)
    return inventory


def empty_inventory():
    return {'_meta': {'hostvars': {}}}


def main():
    inventory = {}

    # Read the command line args passed to the script.
    parser = argparse.ArgumentParser()
    parser.add_argument('--list', action = 'store_true')
    parser.add_argument('--host', action = 'store')
    args = parser.parse_args()

    if args.list:
       inventory = get_inventory()
        # Called with `--host [hostname]`.
    elif args.host:
        # Not implemented, because we have no host specific vars for the task
        inventory = empty_inventory()
        # If no groups or vars are present, return an empty inventory.
    else:
        inventory = empty_inventory()

    print json.dumps(inventory, indent=4, sort_keys=True)
    #print json.dumps(inventory)


if __name__ == '__main__':
    main()
