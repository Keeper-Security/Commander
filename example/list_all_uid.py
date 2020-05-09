# Show all UIDs in Vault
import logging
logger = logging.getLogger(__name__)
sHandler = logging.StreamHandler()
sHandler.setLevel(logging.INFO)
logger.addHandler(sHandler)
logfilenode = __file__.rsplit('.')[0]
handler = logging.FileHandler(f"{logfilenode}.log")
handler.setLevel(logging.INFO)
formatter = logging.Formatter(
    '%(asctime)s - %(name)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)
import sys
import os
sys.path.append("..")
from keepercommander import api, params


if __name__ == '__main__':
    try:
        user = sys.argv[1]
    except IndexError:
        try:
            user = os.environ['user']
        except KeyError:
            user = input("User:")
    try:
        password = sys.argv[2]
    except IndexError:
        try:
            password = os.environ['password']
        except KeyError:
            from getpass import getpass
            password = getpass('Password:')
    # config = {'user': user, 'password': password}
    params = params.KeeperParams()  # config=config)
    params.user = user
    params.password = password
    api.login(params)
    api.sync_down(params)
    MAX_REPEAT = 999
    logger.setLevel(logging.INFO)
    for repeat, uid in enumerate(params.record_cache):
        if repeat >= MAX_REPEAT:
            logger.info(f"Exitting because of over limit {repeat}")
            break
        print(f"{uid}")

    exit(0) # to suppress warning of 'Exit without exit code'