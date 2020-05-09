# Remove "http://sn" login_url
import logging
# logger.basicConfig(filename=f"{__name__}.log")
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
    session_token = api.login(params)
    api.sync_down(params)
    sn_url = 'http://sn'
    MAX_REPEAT = 999
    logger.setLevel(logging.INFO)
    for repeat, uid in enumerate(params.record_cache):
        if repeat >= MAX_REPEAT:
            logger.info(f"Exitting because of over repeat limit {repeat}")
            break
        rec = api.get_record(params, uid)
        if rec.login_url == sn_url:
            rec.login_url = '' # set string empty
            api.update_record(params, rec)
            logger.info(f"sn_url is erased at {uid} : {rec.title}")

    exit(0) # to suppress warning of 'Exit without exit code'