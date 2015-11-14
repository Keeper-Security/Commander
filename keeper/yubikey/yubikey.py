#  _  __  
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|            
#
# Keeper Commander 
# Copyright 2015 Keeper Security Inc.
# Contact: ops@keepersecurity.com
#

import yubico

def get_response(challenge):
    try:
        YK = yubico.find_yubikey()
        response = YK.challenge_response(challenge.encode(), slot=2)

    except yubico.yubico_exception.YubicoError as inst:
        print("ERROR: %s" % inst.reason)
        return ''

    # Workaround for http://bugs.python.org/issue24596
    del YK 

    hexresponse = yubico.yubico_util.hexdump(response, length=20).strip('0000')
    formattedresponse = ''.join(hexresponse.split())

    return formattedresponse
