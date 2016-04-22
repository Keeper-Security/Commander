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

"""Commander Plugin for Rotating AWS passwords
   Dependencies:
       pip3 install awscli
"""

def rotate(record, newpassword):
    """
    @type record: Record
    """
    try:
        pipe = subprocess.Popen(['aws',
                                 'iam',
                                 'update-login-profile',
                                 '--user-name={0}'.format(record.login),
                                 '--password={0}'.format(newpassword)],
                                stdin=subprocess.PIPE,
                                stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE)

        (output1, error1) = pipe.communicate(timeout=3)
        if pipe.poll() == 0:
            record.password = newpassword
            return True

        pipe = subprocess.Popen(['aws',
                                 'iam',
                                 'create-login-profile',
                                 '--user-name={0}'.format(record.login),
                                 '--password={0}'.format(newpassword)],
                                stdin=subprocess.PIPE,
                                stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE)

        (output1, error1) = pipe.communicate(timeout=3)
        if pipe.poll() == 0:
            record.password = newpassword
            return True

    except Exception as e:
        print(e)

    return False
