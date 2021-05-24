#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander
# Copyright 2021 Keeper Security Inc.
# Contact: ops@keepersecurity.com
#
import json
import logging
import sys

import requests

from . import __version__, display


def is_up_to_date_version():

    curr_git_version = None
    version_comparison = None
    release_download_url = 'https://github.com/Keeper-Security/Commander/releases'

    try:
        release_details = get_latest_release_details()
        release_download_url = release_details.get('release_url')
        this_app_version = __version__
        curr_git_version = release_details.get('tag')[1:]

        version_comparison = __version_compare(this_app_version, curr_git_version)

    except requests.exceptions.HTTPError as errh:
        logging.debug("Http Error:", errh)
    except requests.exceptions.ConnectionError as errc:
        logging.debug("Error Connecting:", errc)
    except requests.exceptions.Timeout as errt:
        logging.debug("Timeout Error:", errt)
    except requests.exceptions.RequestException as err:
        logging.debug("Request Error:", err)

    return {
        'is_up_to_date': version_comparison >= 0 if version_comparison else None,
        'current_github_version': curr_git_version,
        'new_version_download_url': release_download_url
    }


# Determine if this app is running as a python script or an installed binary (PyInstaller)
def is_binary_app():
    # see: https://pyinstaller.readthedocs.io/en/stable/runtime-information.html#run-time-information
    return getattr(sys, 'frozen', False) and hasattr(sys, '_MEIPASS')


def get_latest_release_details():

    repo_owner = "Keeper-Security"
    repo_name = "Commander"
    repo_latest_release_api_url = 'https://api.github.com/repos/%s/%s/releases/latest' % (repo_owner, repo_name)

    rs = requests.get(repo_latest_release_api_url, timeout=5)

    rs_dict = json.loads(rs.text)

    latest_tag_name = rs_dict.get('tag_name')
    publish_date = rs_dict.get('published_at')
    release_url = rs_dict.get('html_url')

    return {
        'tag': latest_tag_name,
        'publish_date': publish_date,
        'release_url': release_url
    }


def __version_compare(v1, v2):

    """
      Compare two Commander version versions and will return:
         1 if version 1 is bigger
         0 if equal
        -1 if version 2 is bigger
    """
    # This will split both the versions by '.'
    arr1 = v1.split(".")
    arr2 = v2.split(".")
    n = len(arr1)
    m = len(arr2)

    # converts to integer from string
    arr1 = [int(i) for i in arr1]
    arr2 = [int(i) for i in arr2]

    # compares which list is bigger and fills
    # smaller list with zero (for unequal delimeters)
    if n > m:
        for i in range(m, n):
            arr2.append(0)
    elif m > n:
        for i in range(n, m):
            arr1.append(0)

    # returns 1 if version 1 is bigger and -1 if
    # version 2 is bigger and 0 if equal
    for i in range(len(arr1)):
        if arr1[i] > arr2[i]:
            return 1
        elif arr2[i] > arr1[i]:
            return -1
    return 0


def welcome_print_version():

    this_app_version = __version__

    ver_info = is_up_to_date_version()

    if ver_info.get('is_up_to_date') is None:
        logging.debug(display.bcolors.WARNING + "It appears that the internet connection is offline." + display.bcolors.ENDC)

    elif not ver_info.get('is_up_to_date'):
        print(display.bcolors.WARNING +
              (" Your version of the Commander CLI is %s, the current version is %s.\n Use the ‘version’ "
               "command for more details.\n") % (this_app_version, ver_info.get('current_github_version')) + display.bcolors.ENDC
              )
    else:
        pass
        # print("Your version of the Commander CLI is %s." % this_app_version)
