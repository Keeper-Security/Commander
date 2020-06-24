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

import logging
import os
from ...error import Error

if os.name == 'posix':
    from pexpect import pxssh, exceptions


    """Commander Plugin for SSH Command
    Dependencies: s
        pip3 install pexpect
    """

    def rotate(record, newpassword):
        """ Grab any required fields from the record """
        user = record.login
        oldpassword = record.password
        result = False
        host = record.get('cmdr:host')
        try:
            s = pxssh.pxssh()
            s.login(host, user, oldpassword, sync_multiplier=3)
            s.sendline('passwd')
            i = s.expect(['[Oo]ld.*[Pp]assword', '[Cc]urrent.*[Pp]assword', '[Nn]ew.*[Pp]assword'])
            if i == 0 or i == 1:
                s.sendline(oldpassword)
                i = s.expect(['[Nn]ew.*[Pp]assword', 'password unchanged'])
                if i != 0:
                    return False

            s.sendline(newpassword)
            s.expect("Retype [Nn]ew.*[Pp]assword:")
            s.sendline(newpassword)
            s.prompt()

            pass_result = s.before

            if "success" in str(pass_result):
                logging.info("Password changed successfully")
                record.password = newpassword
                result = True
            else:
                logging.error("Password change failed: ", pass_result)

            s.logout()
        except exceptions.TIMEOUT as t:
            logging.error("Timed out waiting for response.")
        except pxssh.ExceptionPxssh as e:
            logging.error("Failed to login with ssh.")

        return result

elif os.name == 'nt':
    import threading, queue
    import paramiko
    import sys
    import re
    from socket import timeout
    import time

    """Commander Plugin for SSH Command
    Dependencies: s
        pip3 install paramiko
    """

    def rotate(record, newpassword):
        """ Grab any required fields from the record """
        user = record.login
        oldpassword = record.password
        result = False
        host = record.get('cmdr:host')
        try:
            ssh_client =paramiko.SSHClient()
            ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh_client.connect(hostname=host,username=user,password=oldpassword)
            transport = ssh_client.get_transport()
            chan = transport.open_session()
            chan.get_pty()
            chan.invoke_shell() # establish connection and invoke shell to interact
            res_que = queue.Queue() # Using thread to monitor responses in shell
            def writeall(sock, que):
                while True:
                    try:
                        data = sock.recv(444)
                    except timeout:
                        pass_result = "Waited for 10Seconds. No Remote response."
                        sys.stdout.write(pass_result)
                        que.put(pass_result)
                        sys.stdout.flush()
                        sock.close()
                        break
                    if not data:
                        sys.stdout.write("\r\n*** EOF ***\r\n\r\n")
                        sys.stdout.flush()
                        break
                    formatted_data = data.decode()
                    formatted_data = formatted_data.replace('\r\n', '\r\n\t')
                    sys.stdout.write("\t" + formatted_data)
                    sys.stdout.flush()
                    if re.search("new .*password", data.decode(), re.I):
                        chan.send(newpassword+"\n")
                    elif re.search("current password", data.decode(), re.I):
                        chan.send(oldpassword+"\n")
                    elif re.search("\[sudo\] password for .*", data.decode(), re.I):
                        chan.send(oldpassword+"\n")
                    elif re.search('password unchanged', data.decode(), re.I):
                        pass_result = data.decode()
                        que.put(pass_result)
                        sock.close()
                        break
                    elif re.search('password updated successfully', data.decode(), re.I):#Success!
                        pass_result = data.decode()
                        with que.mutex:
                            que.queue.clear()
                        que.put(pass_result)
                        sock.close()
                        break
                    else:
                        pass_result = f"Unknown response from server! : {data.decode()}"
                        que.put(pass_result)

            writer = threading.Thread(target=writeall, args=(chan, res_que))
            writer.start()
            chan.settimeout(10)
            time.sleep(3) # Wait to establish connection
            chan.send('passwd\n') # Send command
            writer.join() # Wait for command to complete execution
            result_list = []
            while not res_que.empty():
                result_list.append(res_que.get())
            pass_result = result_list[-1] # Get the last confirmation from passwd command

            if " success" in str(pass_result):
                logging.info("\nPassword changed successfully")
                record.password = newpassword
                result = True
            else:
                logging.error("Password change failed: ", pass_result)

        except Exception as e:
            logging.error(f"Failed to login with ssh. : {e}")

        return result

else:
    raise Exception(f'Not available on {os.name} operating system')
