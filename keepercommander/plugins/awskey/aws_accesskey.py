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

"""Commander Plugin for Rotating AWS Access Keys
   Dependencies:
       pip3 install awscli
"""

def delete_aws_key(user, key_id):
    pipe = subprocess.Popen(['aws',
                             'iam',
                             'delete-access-key',
                             '--user-name={0}'.format(user),
                             '--access-key-id={0}'.format(key_id)
                             ],
                            stdin=subprocess.PIPE,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE)

    (output1, error1) = pipe.communicate(timeout=3)
#    if pipe.poll() != 0:
#        if error1 is not None:
#            print("Warning: Delete AWS access key for user {1}: {0}".format(error1.decode(), user))


def rotate(record, newpassword):
    """
    @type record: Record
    """
    try:
        old_key_id = record.get("cmdr:aws_key_id")
        if old_key_id:
            delete_aws_key(record.login,old_key_id)

        pipe = subprocess.Popen(['aws',
                                 'iam',
                                 'create-access-key',
                                 '--user-name={0}'.format(record.login)],
                                stdin=subprocess.PIPE,
                                stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE)
        (output1, error1) = pipe.communicate(timeout=3)
        if pipe.poll() == 0:
            ret = json.loads(output1.decode())
            key = ret["AccessKey"]
            if key is not None:
                new_key_id = key["AccessKeyId"]
                new_key_secret = key["SecretAccessKey"]
                record.set_field("cmdr:aws_key_id", new_key_id)
                record.set_field("cmdr:aws_key_secret", new_key_secret)

                return True
        else:
            if error1 is not None:
                print("Error: Create AWS access key for user {1}: {0}".format(error1.decode(), record.login))

    except Exception as e:
        print(e)

    return False
