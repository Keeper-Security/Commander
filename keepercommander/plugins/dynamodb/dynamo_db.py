# -*- coding: utf-8 -*-
#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander
# Copyright 2016 Keeper Security Inc.
# Contact: ops@keepersecurity.com
#

import subprocess
import json

"""Commander Plugin for Updating attribute in DynamoDB
   Dependencies:
       pip3 install awscli
"""


def rotate(record, newpassword):
    return False
    """
    @type record: Record
    """
    try:
        dynamo_table = record.get("cmdr:dyn_tbl_name")
        if not dynamo_table:
            print("\"{0}\" custom field is missing. This field containd DynamoDB table name".format("cmdr:dyn_tbl_name"))
            return False

        dynamo_attribute = record.get("cmdr:dyn_attr_name")
        if not dynamo_attribute:
            print("\"{0}\" custom field is missing. This field containd DynamoDB attribute name which value will be rotated".format("cmdr:dyn_attr_name"))
            return False

        dynamo_key_value = record.login
        if not dynamo_attribute:
            print("The 'login' field is empty. This field contains item key value.")
            return False

        dynamo_key_name = record.get("cmdr:dyn_key_name")
        if not dynamo_key_name:
            pipe = subprocess.Popen(['aws',
                                     'dynamodb',
                                     'describe-table',
                                     '--table-name=', dynamo_table
                                     ],
                                    stdin=subprocess.PIPE,
                                    stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE)
            (output1, error1) = pipe.communicate(timeout=3)
            if pipe.poll() == 0:
                ret = json.loads(output1.decode())
                key = ret["Table"]["KeySchema"]
                if not key:
                    print('Error: DynamoDB: describe-table: no key information')
                    return False
                dynamo_key_name = key[0]["AttributeName"]
                record.set_field("cmdr:dyn_key_name", dynamo_key_name)
            else:
                if not error1:
                    print("Error: DynamoDB: describe-table: {0}".format(error1.decode()))

        key = json.dumps({dynamo_key_name: {"S": dynamo_key_value}})
        attr = json.dumps({dynamo_attribute: {"Action": "PUT", "Value": {"S": newpassword}}})
        pipe = subprocess.Popen(['aws',
                                 'dynamodb',
                                 'update-item',
                                 '--table-name', dynamo_table,
                                 '--key', key,
                                 '--attribute-updates', attr
                                 ],
                                stdin=subprocess.PIPE,
                                stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE)
        (output1, error1) = pipe.communicate(timeout=3)
        if pipe.poll() == 0:
            record.password = newpassword
            return True
        else:
            if not error1:
                print("Error: DynamoDB: update-item: {0}".format(error1.decode()))

    except Exception as e:
        print(e)

    return False
