#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander
# Copyright 2025 Keeper Security Inc.
# Contact: ops@keepersecurity.com
#
"""Sample-data ("Discovery Playground") generator for ``pam project import -s``.

Everything the ``--sample-data`` flow needs lives in this single module:

    1. Constants           - GATEWAY_DEPENDS_ON, SECCOMP_B64, SECCOMP_URL, images
    2. Credentials         - PlaygroundCredentials (+ RSA SSH keygen)
    3. Session             - PlaygroundSession (creds -> Pam* objects -> batch engine
                             -> compose -> save)
    4. Compose             - build_compose() + per-service YAML builders
    5. Output              - save_compose_and_seccomp()

Vault record creation uses ``BatchPamImportEngine`` (same path as
``pam project import`` / ``extend``). Credentials are generated once per run
(no hard-coded secrets) and shared between the vault records and the generated
``docker-compose.yaml`` so the two always agree. The compose template mirrors
the discovery-playground repo's ``origin/main:docker-compose.yaml``.
"""

from __future__ import annotations

import base64
import contextlib
import json
import logging
import os
import re
import tempfile
from datetime import datetime
from secrets import token_hex
from typing import Any, Callable, Dict, List, Optional

from ... import api
from ...display import bcolors
from ...generator import KeeperPasswordGenerator, DEFAULT_PASSWORD_LENGTH
from .base import (
    PamDatabaseObject,
    PamDirectoryObject,
    PamMachineObject,
    PamRemoteBrowserObject,
    PamRotationParams,
    PamUserObject,
    find_user,
    get_admin_credential,
    get_launch_credential,
    resolve_script_creds,
    set_launch_record_uid,
    set_user_record_uid,
)
from .batch_pipeline import BatchPamImportEngine, assign_uids

# On-demand rotation profile used by playground users that the origin
# path configured via PAMCreateRecordRotationCommand(on_demand=True, ...).
_ON_DEMAND_ROTATION = {
    "rotation": "general",
    "enabled": "on",
    "schedule": {"type": "on-demand"},
    "password_complexity": "20,4,4,4,4",
}

# =====================================================================
# 1. Constants
# =====================================================================

#: Gateway image per KeeperPAM Setup Steps (supersedes origin gateway-dev:x.y.z).
GATEWAY_IMAGE = "keeper/gateway:latest"

#: Subnet for the generated docker network (matches discovery-playground origin).
NETWORK_SUBNET = "192.168.1.0/24"

#: Gateway ``depends_on`` list (11 services).  Origin lists only 8; the three
#: extra backends (db-mssql, db-mongo, server-telnet) are a deliberate KC
#: improvement so the gateway starts after every backend it exercises.
GATEWAY_DEPENDS_ON = [
    "db-mysql-1",
    "db-postgres-1",
    "db-mariadb-1",
    "db-mssql",
    # "db-mongo",  # disabled with the MongoDB record (see _create_mongodb_records)
    "server-ssh-with-pwd-1",
    "server-ssh-with-key-1",
    "server-openldap-1",
    "server-vnc",
    "server-rdp",
    "server-telnet",
]

#: Canonical seccomp profile URL (KeeperPAM Setup Steps).  Printed to the user
#: after generation; the profile bytes themselves are embedded below.
SECCOMP_URL = (
    "https://raw.githubusercontent.com/Keeper-Security/KeeperPAM/"
    "refs/heads/main/gateway/docker-seccomp.json"
)

# Base64 of gateway/docker-seccomp.json (KeeperPAM main; byte-identical to
# discovery-playground/docker-seccomp.json - 12,710 bytes,
# sha256 268fe62ef534293fb1af851cea3da0f1a5ce386e772fd3cb4aaa1c7a4f88aa6b).
# Wrapped for readability; whitespace is stripped before decoding.
_SECCOMP_B64_WRAPPED = """
ewoJImRlZmF1bHRBY3Rpb24iOiAiU0NNUF9BQ1RfRVJSTk8iLAoJImRlZmF1bHRFcnJub1JldCI6
IDEsCgkiYXJjaE1hcCI6IFsKCQl7CgkJCSJhcmNoaXRlY3R1cmUiOiAiU0NNUF9BUkNIX1g4Nl82
NCIsCgkJCSJzdWJBcmNoaXRlY3R1cmVzIjogWwoJCQkJIlNDTVBfQVJDSF9YODYiLAoJCQkJIlND
TVBfQVJDSF9YMzIiCgkJCV0KCQl9LAoJCXsKCQkJImFyY2hpdGVjdHVyZSI6ICJTQ01QX0FSQ0hf
QUFSQ0g2NCIsCgkJCSJzdWJBcmNoaXRlY3R1cmVzIjogWwoJCQkJIlNDTVBfQVJDSF9BUk0iCgkJ
CV0KCQl9LAoJCXsKCQkJImFyY2hpdGVjdHVyZSI6ICJTQ01QX0FSQ0hfTUlQUzY0IiwKCQkJInN1
YkFyY2hpdGVjdHVyZXMiOiBbCgkJCQkiU0NNUF9BUkNIX01JUFMiLAoJCQkJIlNDTVBfQVJDSF9N
SVBTNjROMzIiCgkJCV0KCQl9LAoJCXsKCQkJImFyY2hpdGVjdHVyZSI6ICJTQ01QX0FSQ0hfTUlQ
UzY0TjMyIiwKCQkJInN1YkFyY2hpdGVjdHVyZXMiOiBbCgkJCQkiU0NNUF9BUkNIX01JUFMiLAoJ
CQkJIlNDTVBfQVJDSF9NSVBTNjQiCgkJCV0KCQl9LAoJCXsKCQkJImFyY2hpdGVjdHVyZSI6ICJT
Q01QX0FSQ0hfTUlQU0VMNjQiLAoJCQkic3ViQXJjaGl0ZWN0dXJlcyI6IFsKCQkJCSJTQ01QX0FS
Q0hfTUlQU0VMIiwKCQkJCSJTQ01QX0FSQ0hfTUlQU0VMNjROMzIiCgkJCV0KCQl9LAoJCXsKCQkJ
ImFyY2hpdGVjdHVyZSI6ICJTQ01QX0FSQ0hfTUlQU0VMNjROMzIiLAoJCQkic3ViQXJjaGl0ZWN0
dXJlcyI6IFsKCQkJCSJTQ01QX0FSQ0hfTUlQU0VMIiwKCQkJCSJTQ01QX0FSQ0hfTUlQU0VMNjQi
CgkJCV0KCQl9LAoJCXsKCQkJImFyY2hpdGVjdHVyZSI6ICJTQ01QX0FSQ0hfUzM5MFgiLAoJCQki
c3ViQXJjaGl0ZWN0dXJlcyI6IFsKCQkJCSJTQ01QX0FSQ0hfUzM5MCIKCQkJXQoJCX0sCgkJewoJ
CQkiYXJjaGl0ZWN0dXJlIjogIlNDTVBfQVJDSF9SSVNDVjY0IiwKCQkJInN1YkFyY2hpdGVjdHVy
ZXMiOiBudWxsCgkJfQoJXSwKCSJzeXNjYWxscyI6IFsKCQl7CgkJCSJuYW1lcyI6IFsKCQkJCSJh
Y2NlcHQiLAoJCQkJImFjY2VwdDQiLAoJCQkJImFjY2VzcyIsCgkJCQkiYWRqdGltZXgiLAoJCQkJ
ImFsYXJtIiwKCQkJCSJiaW5kIiwKCQkJCSJicmsiLAoJCQkJImNhcGdldCIsCgkJCQkiY2Fwc2V0
IiwKCQkJCSJjaGRpciIsCgkJCQkiY2htb2QiLAoJCQkJImNob3duIiwKCQkJCSJjaG93bjMyIiwK
CQkJCSJjaHJvb3QiLAoJCQkJImNsb2NrX2FkanRpbWUiLAoJCQkJImNsb2NrX2FkanRpbWU2NCIs
CgkJCQkiY2xvY2tfZ2V0cmVzIiwKCQkJCSJjbG9ja19nZXRyZXNfdGltZTY0IiwKCQkJCSJjbG9j
a19nZXR0aW1lIiwKCQkJCSJjbG9ja19nZXR0aW1lNjQiLAoJCQkJImNsb2NrX25hbm9zbGVlcCIs
CgkJCQkiY2xvY2tfbmFub3NsZWVwX3RpbWU2NCIsCgkJCQkiY2xvbmUiLAoJCQkJImNsb3NlIiwK
CQkJCSJjbG9zZV9yYW5nZSIsCgkJCQkiY29ubmVjdCIsCgkJCQkiY29weV9maWxlX3JhbmdlIiwK
CQkJCSJjcmVhdCIsCgkJCQkiZHVwIiwKCQkJCSJkdXAyIiwKCQkJCSJkdXAzIiwKCQkJCSJlcG9s
bF9jcmVhdGUiLAoJCQkJImVwb2xsX2NyZWF0ZTEiLAoJCQkJImVwb2xsX2N0bCIsCgkJCQkiZXBv
bGxfY3RsX29sZCIsCgkJCQkiZXBvbGxfcHdhaXQiLAoJCQkJImVwb2xsX3B3YWl0MiIsCgkJCQki
ZXBvbGxfd2FpdCIsCgkJCQkiZXBvbGxfd2FpdF9vbGQiLAoJCQkJImV2ZW50ZmQiLAoJCQkJImV2
ZW50ZmQyIiwKCQkJCSJleGVjdmUiLAoJCQkJImV4ZWN2ZWF0IiwKCQkJCSJleGl0IiwKCQkJCSJl
eGl0X2dyb3VwIiwKCQkJCSJmYWNjZXNzYXQiLAoJCQkJImZhY2Nlc3NhdDIiLAoJCQkJImZhZHZp
c2U2NCIsCgkJCQkiZmFkdmlzZTY0XzY0IiwKCQkJCSJmYWxsb2NhdGUiLAoJCQkJImZhbm90aWZ5
X21hcmsiLAoJCQkJImZjaGRpciIsCgkJCQkiZmNobW9kIiwKCQkJCSJmY2htb2RhdCIsCgkJCQki
ZmNob3duIiwKCQkJCSJmY2hvd24zMiIsCgkJCQkiZmNob3duYXQiLAoJCQkJImZjbnRsIiwKCQkJ
CSJmY250bDY0IiwKCQkJCSJmZGF0YXN5bmMiLAoJCQkJImZnZXR4YXR0ciIsCgkJCQkiZmxpc3R4
YXR0ciIsCgkJCQkiZmxvY2siLAoJCQkJImZvcmsiLAoJCQkJImZyZW1vdmV4YXR0ciIsCgkJCQki
ZnNldHhhdHRyIiwKCQkJCSJmc3RhdCIsCgkJCQkiZnN0YXQ2NCIsCgkJCQkiZnN0YXRhdDY0IiwK
CQkJCSJmc3RhdGZzIiwKCQkJCSJmc3RhdGZzNjQiLAoJCQkJImZzeW5jIiwKCQkJCSJmdHJ1bmNh
dGUiLAoJCQkJImZ0cnVuY2F0ZTY0IiwKCQkJCSJmdXRleCIsCgkJCQkiZnV0ZXhfdGltZTY0IiwK
CQkJCSJmdXRleF93YWl0diIsCgkJCQkiZnV0aW1lc2F0IiwKCQkJCSJnZXRjcHUiLAoJCQkJImdl
dGN3ZCIsCgkJCQkiZ2V0ZGVudHMiLAoJCQkJImdldGRlbnRzNjQiLAoJCQkJImdldGVnaWQiLAoJ
CQkJImdldGVnaWQzMiIsCgkJCQkiZ2V0ZXVpZCIsCgkJCQkiZ2V0ZXVpZDMyIiwKCQkJCSJnZXRn
aWQiLAoJCQkJImdldGdpZDMyIiwKCQkJCSJnZXRncm91cHMiLAoJCQkJImdldGdyb3VwczMyIiwK
CQkJCSJnZXRpdGltZXIiLAoJCQkJImdldHBlZXJuYW1lIiwKCQkJCSJnZXRwZ2lkIiwKCQkJCSJn
ZXRwZ3JwIiwKCQkJCSJnZXRwaWQiLAoJCQkJImdldHBwaWQiLAoJCQkJImdldHByaW9yaXR5IiwK
CQkJCSJnZXRyYW5kb20iLAoJCQkJImdldHJlc2dpZCIsCgkJCQkiZ2V0cmVzZ2lkMzIiLAoJCQkJ
ImdldHJlc3VpZCIsCgkJCQkiZ2V0cmVzdWlkMzIiLAoJCQkJImdldHJsaW1pdCIsCgkJCQkiZ2V0
X3JvYnVzdF9saXN0IiwKCQkJCSJnZXRydXNhZ2UiLAoJCQkJImdldHNpZCIsCgkJCQkiZ2V0c29j
a25hbWUiLAoJCQkJImdldHNvY2tvcHQiLAoJCQkJImdldF90aHJlYWRfYXJlYSIsCgkJCQkiZ2V0
dGlkIiwKCQkJCSJnZXR0aW1lb2ZkYXkiLAoJCQkJImdldHVpZCIsCgkJCQkiZ2V0dWlkMzIiLAoJ
CQkJImdldHhhdHRyIiwKCQkJCSJpbm90aWZ5X2FkZF93YXRjaCIsCgkJCQkiaW5vdGlmeV9pbml0
IiwKCQkJCSJpbm90aWZ5X2luaXQxIiwKCQkJCSJpbm90aWZ5X3JtX3dhdGNoIiwKCQkJCSJpb19j
YW5jZWwiLAoJCQkJImlvY3RsIiwKCQkJCSJpb19kZXN0cm95IiwKCQkJCSJpb19nZXRldmVudHMi
LAoJCQkJImlvX3BnZXRldmVudHMiLAoJCQkJImlvX3BnZXRldmVudHNfdGltZTY0IiwKCQkJCSJp
b3ByaW9fZ2V0IiwKCQkJCSJpb3ByaW9fc2V0IiwKCQkJCSJpb19zZXR1cCIsCgkJCQkiaW9fc3Vi
bWl0IiwKCQkJCSJpcGMiLAoJCQkJImtpbGwiLAoJCQkJImxhbmRsb2NrX2FkZF9ydWxlIiwKCQkJ
CSJsYW5kbG9ja19jcmVhdGVfcnVsZXNldCIsCgkJCQkibGFuZGxvY2tfcmVzdHJpY3Rfc2VsZiIs
CgkJCQkibGNob3duIiwKCQkJCSJsY2hvd24zMiIsCgkJCQkibGdldHhhdHRyIiwKCQkJCSJsaW5r
IiwKCQkJCSJsaW5rYXQiLAoJCQkJImxpc3RlbiIsCgkJCQkibGlzdHhhdHRyIiwKCQkJCSJsbGlz
dHhhdHRyIiwKCQkJCSJfbGxzZWVrIiwKCQkJCSJscmVtb3ZleGF0dHIiLAoJCQkJImxzZWVrIiwK
CQkJCSJsc2V0eGF0dHIiLAoJCQkJImxzdGF0IiwKCQkJCSJsc3RhdDY0IiwKCQkJCSJtYWR2aXNl
IiwKCQkJCSJtZW1iYXJyaWVyIiwKCQkJCSJtZW1mZF9jcmVhdGUiLAoJCQkJIm1lbWZkX3NlY3Jl
dCIsCgkJCQkibWluY29yZSIsCgkJCQkibWtkaXIiLAoJCQkJIm1rZGlyYXQiLAoJCQkJIm1rbm9k
IiwKCQkJCSJta25vZGF0IiwKCQkJCSJtbG9jayIsCgkJCQkibWxvY2syIiwKCQkJCSJtbG9ja2Fs
bCIsCgkJCQkibW1hcCIsCgkJCQkibW1hcDIiLAoJCQkJIm1vdW50IiwKCQkJCSJtcHJvdGVjdCIs
CgkJCQkibXFfZ2V0c2V0YXR0ciIsCgkJCQkibXFfbm90aWZ5IiwKCQkJCSJtcV9vcGVuIiwKCQkJ
CSJtcV90aW1lZHJlY2VpdmUiLAoJCQkJIm1xX3RpbWVkcmVjZWl2ZV90aW1lNjQiLAoJCQkJIm1x
X3RpbWVkc2VuZCIsCgkJCQkibXFfdGltZWRzZW5kX3RpbWU2NCIsCgkJCQkibXFfdW5saW5rIiwK
CQkJCSJtcmVtYXAiLAoJCQkJIm1zZ2N0bCIsCgkJCQkibXNnZ2V0IiwKCQkJCSJtc2dyY3YiLAoJ
CQkJIm1zZ3NuZCIsCgkJCQkibXN5bmMiLAoJCQkJIm11bmxvY2siLAoJCQkJIm11bmxvY2thbGwi
LAoJCQkJIm11bm1hcCIsCgkJCQkibmFtZV90b19oYW5kbGVfYXQiLAoJCQkJIm5hbm9zbGVlcCIs
CgkJCQkibmV3ZnN0YXRhdCIsCgkJCQkiX25ld3NlbGVjdCIsCgkJCQkib3BlbiIsCgkJCQkib3Bl
bmF0IiwKCQkJCSJvcGVuYXQyIiwKCQkJCSJwYXVzZSIsCgkJCQkicGlkZmRfb3BlbiIsCgkJCQki
cGlkZmRfc2VuZF9zaWduYWwiLAoJCQkJInBpcGUiLAoJCQkJInBpcGUyIiwKCQkJCSJwa2V5X2Fs
bG9jIiwKCQkJCSJwa2V5X2ZyZWUiLAoJCQkJInBrZXlfbXByb3RlY3QiLAoJCQkJInBvbGwiLAoJ
CQkJInBwb2xsIiwKCQkJCSJwcG9sbF90aW1lNjQiLAoJCQkJInByY3RsIiwKCQkJCSJwcmVhZDY0
IiwKCQkJCSJwcmVhZHYiLAoJCQkJInByZWFkdjIiLAoJCQkJInBybGltaXQ2NCIsCgkJCQkicHJv
Y2Vzc19tcmVsZWFzZSIsCgkJCQkicHNlbGVjdDYiLAoJCQkJInBzZWxlY3Q2X3RpbWU2NCIsCgkJ
CQkicHdyaXRlNjQiLAoJCQkJInB3cml0ZXYiLAoJCQkJInB3cml0ZXYyIiwKCQkJCSJyZWFkIiwK
CQkJCSJyZWFkYWhlYWQiLAoJCQkJInJlYWRsaW5rIiwKCQkJCSJyZWFkbGlua2F0IiwKCQkJCSJy
ZWFkdiIsCgkJCQkicmVjdiIsCgkJCQkicmVjdmZyb20iLAoJCQkJInJlY3ZtbXNnIiwKCQkJCSJy
ZWN2bW1zZ190aW1lNjQiLAoJCQkJInJlY3Ztc2ciLAoJCQkJInJlbWFwX2ZpbGVfcGFnZXMiLAoJ
CQkJInJlbW92ZXhhdHRyIiwKCQkJCSJyZW5hbWUiLAoJCQkJInJlbmFtZWF0IiwKCQkJCSJyZW5h
bWVhdDIiLAoJCQkJInJlc3RhcnRfc3lzY2FsbCIsCgkJCQkicm1kaXIiLAoJCQkJInJzZXEiLAoJ
CQkJInJ0X3NpZ2FjdGlvbiIsCgkJCQkicnRfc2lncGVuZGluZyIsCgkJCQkicnRfc2lncHJvY21h
c2siLAoJCQkJInJ0X3NpZ3F1ZXVlaW5mbyIsCgkJCQkicnRfc2lncmV0dXJuIiwKCQkJCSJydF9z
aWdzdXNwZW5kIiwKCQkJCSJydF9zaWd0aW1lZHdhaXQiLAoJCQkJInJ0X3NpZ3RpbWVkd2FpdF90
aW1lNjQiLAoJCQkJInJ0X3Rnc2lncXVldWVpbmZvIiwKCQkJCSJzY2hlZF9nZXRhZmZpbml0eSIs
CgkJCQkic2NoZWRfZ2V0YXR0ciIsCgkJCQkic2NoZWRfZ2V0cGFyYW0iLAoJCQkJInNjaGVkX2dl
dF9wcmlvcml0eV9tYXgiLAoJCQkJInNjaGVkX2dldF9wcmlvcml0eV9taW4iLAoJCQkJInNjaGVk
X2dldHNjaGVkdWxlciIsCgkJCQkic2NoZWRfcnJfZ2V0X2ludGVydmFsIiwKCQkJCSJzY2hlZF9y
cl9nZXRfaW50ZXJ2YWxfdGltZTY0IiwKCQkJCSJzY2hlZF9zZXRhZmZpbml0eSIsCgkJCQkic2No
ZWRfc2V0YXR0ciIsCgkJCQkic2NoZWRfc2V0cGFyYW0iLAoJCQkJInNjaGVkX3NldHNjaGVkdWxl
ciIsCgkJCQkic2NoZWRfeWllbGQiLAoJCQkJInNlY2NvbXAiLAoJCQkJInNlbGVjdCIsCgkJCQki
c2VtY3RsIiwKCQkJCSJzZW1nZXQiLAoJCQkJInNlbW9wIiwKCQkJCSJzZW10aW1lZG9wIiwKCQkJ
CSJzZW10aW1lZG9wX3RpbWU2NCIsCgkJCQkic2VuZCIsCgkJCQkic2VuZGZpbGUiLAoJCQkJInNl
bmRmaWxlNjQiLAoJCQkJInNlbmRtbXNnIiwKCQkJCSJzZW5kbXNnIiwKCQkJCSJzZW5kdG8iLAoJ
CQkJInNldGZzZ2lkIiwKCQkJCSJzZXRmc2dpZDMyIiwKCQkJCSJzZXRmc3VpZCIsCgkJCQkic2V0
ZnN1aWQzMiIsCgkJCQkic2V0Z2lkIiwKCQkJCSJzZXRnaWQzMiIsCgkJCQkic2V0Z3JvdXBzIiwK
CQkJCSJzZXRncm91cHMzMiIsCgkJCQkic2V0aXRpbWVyIiwKCQkJCSJzZXRwZ2lkIiwKCQkJCSJz
ZXRwcmlvcml0eSIsCgkJCQkic2V0cmVnaWQiLAoJCQkJInNldHJlZ2lkMzIiLAoJCQkJInNldHJl
c2dpZCIsCgkJCQkic2V0cmVzZ2lkMzIiLAoJCQkJInNldHJlc3VpZCIsCgkJCQkic2V0cmVzdWlk
MzIiLAoJCQkJInNldHJldWlkIiwKCQkJCSJzZXRyZXVpZDMyIiwKCQkJCSJzZXRybGltaXQiLAoJ
CQkJInNldF9yb2J1c3RfbGlzdCIsCgkJCQkic2V0c2lkIiwKCQkJCSJzZXRzb2Nrb3B0IiwKCQkJ
CSJzZXRfdGhyZWFkX2FyZWEiLAoJCQkJInNldF90aWRfYWRkcmVzcyIsCgkJCQkic2V0dWlkIiwK
CQkJCSJzZXR1aWQzMiIsCgkJCQkic2V0eGF0dHIiLAoJCQkJInNobWF0IiwKCQkJCSJzaG1jdGwi
LAoJCQkJInNobWR0IiwKCQkJCSJzaG1nZXQiLAoJCQkJInNodXRkb3duIiwKCQkJCSJzaWdhbHRz
dGFjayIsCgkJCQkic2lnbmFsZmQiLAoJCQkJInNpZ25hbGZkNCIsCgkJCQkic2lncHJvY21hc2si
LAoJCQkJInNpZ3JldHVybiIsCgkJCQkic29ja2V0Y2FsbCIsCgkJCQkic29ja2V0cGFpciIsCgkJ
CQkic3BsaWNlIiwKCQkJCSJzdGF0IiwKCQkJCSJzdGF0NjQiLAoJCQkJInN0YXRmcyIsCgkJCQki
c3RhdGZzNjQiLAoJCQkJInN0YXR4IiwKCQkJCSJzeW1saW5rIiwKCQkJCSJzeW1saW5rYXQiLAoJ
CQkJInN5bmMiLAoJCQkJInN5bmNfZmlsZV9yYW5nZSIsCgkJCQkic3luY2ZzIiwKCQkJCSJzeXNp
bmZvIiwKCQkJCSJ0ZWUiLAoJCQkJInRna2lsbCIsCgkJCQkidGltZSIsCgkJCQkidGltZXJfY3Jl
YXRlIiwKCQkJCSJ0aW1lcl9kZWxldGUiLAoJCQkJInRpbWVyX2dldG92ZXJydW4iLAoJCQkJInRp
bWVyX2dldHRpbWUiLAoJCQkJInRpbWVyX2dldHRpbWU2NCIsCgkJCQkidGltZXJfc2V0dGltZSIs
CgkJCQkidGltZXJfc2V0dGltZTY0IiwKCQkJCSJ0aW1lcmZkX2NyZWF0ZSIsCgkJCQkidGltZXJm
ZF9nZXR0aW1lIiwKCQkJCSJ0aW1lcmZkX2dldHRpbWU2NCIsCgkJCQkidGltZXJmZF9zZXR0aW1l
IiwKCQkJCSJ0aW1lcmZkX3NldHRpbWU2NCIsCgkJCQkidGltZXMiLAoJCQkJInRraWxsIiwKCQkJ
CSJ0cnVuY2F0ZSIsCgkJCQkidHJ1bmNhdGU2NCIsCgkJCQkidWdldHJsaW1pdCIsCgkJCQkidW1h
c2siLAoJCQkJInVuYW1lIiwKCQkJCSJ1bmxpbmsiLAoJCQkJInVubGlua2F0IiwKCQkJCSJ1bnNo
YXJlIiwKCQkJCSJ1dGltZSIsCgkJCQkidXRpbWVuc2F0IiwKCQkJCSJ1dGltZW5zYXRfdGltZTY0
IiwKCQkJCSJ1dGltZXMiLAoJCQkJInZmb3JrIiwKCQkJCSJ2bXNwbGljZSIsCgkJCQkid2FpdDQi
LAoJCQkJIndhaXRpZCIsCgkJCQkid2FpdHBpZCIsCgkJCQkid3JpdGUiLAoJCQkJIndyaXRldiIK
CQkJXSwKCQkJImFjdGlvbiI6ICJTQ01QX0FDVF9BTExPVyIKCQl9LAoJCXsKCQkJIm5hbWVzIjog
WwoJCQkJInByb2Nlc3Nfdm1fcmVhZHYiLAoJCQkJInByb2Nlc3Nfdm1fd3JpdGV2IiwKCQkJCSJw
dHJhY2UiCgkJCV0sCgkJCSJhY3Rpb24iOiAiU0NNUF9BQ1RfQUxMT1ciLAoJCQkiaW5jbHVkZXMi
OiB7CgkJCQkibWluS2VybmVsIjogIjQuOCIKCQkJfQoJCX0sCgkJewoJCQkibmFtZXMiOiBbCgkJ
CQkic29ja2V0IgoJCQldLAoJCQkiYWN0aW9uIjogIlNDTVBfQUNUX0FMTE9XIiwKCQkJImFyZ3Mi
OiBbCgkJCQl7CgkJCQkJImluZGV4IjogMCwKCQkJCQkidmFsdWUiOiA0MCwKCQkJCQkib3AiOiAi
U0NNUF9DTVBfTkUiCgkJCQl9CgkJCV0KCQl9LAoJCXsKCQkJIm5hbWVzIjogWwoJCQkJInBlcnNv
bmFsaXR5IgoJCQldLAoJCQkiYWN0aW9uIjogIlNDTVBfQUNUX0FMTE9XIiwKCQkJImFyZ3MiOiBb
CgkJCQl7CgkJCQkJImluZGV4IjogMCwKCQkJCQkidmFsdWUiOiAwLAoJCQkJCSJvcCI6ICJTQ01Q
X0NNUF9FUSIKCQkJCX0KCQkJXQoJCX0sCgkJewoJCQkibmFtZXMiOiBbCgkJCQkicGVyc29uYWxp
dHkiCgkJCV0sCgkJCSJhY3Rpb24iOiAiU0NNUF9BQ1RfQUxMT1ciLAoJCQkiYXJncyI6IFsKCQkJ
CXsKCQkJCQkiaW5kZXgiOiAwLAoJCQkJCSJ2YWx1ZSI6IDgsCgkJCQkJIm9wIjogIlNDTVBfQ01Q
X0VRIgoJCQkJfQoJCQldCgkJfSwKCQl7CgkJCSJuYW1lcyI6IFsKCQkJCSJwZXJzb25hbGl0eSIK
CQkJXSwKCQkJImFjdGlvbiI6ICJTQ01QX0FDVF9BTExPVyIsCgkJCSJhcmdzIjogWwoJCQkJewoJ
CQkJCSJpbmRleCI6IDAsCgkJCQkJInZhbHVlIjogMTMxMDcyLAoJCQkJCSJvcCI6ICJTQ01QX0NN
UF9FUSIKCQkJCX0KCQkJXQoJCX0sCgkJewoJCQkibmFtZXMiOiBbCgkJCQkicGVyc29uYWxpdHki
CgkJCV0sCgkJCSJhY3Rpb24iOiAiU0NNUF9BQ1RfQUxMT1ciLAoJCQkiYXJncyI6IFsKCQkJCXsK
CQkJCQkiaW5kZXgiOiAwLAoJCQkJCSJ2YWx1ZSI6IDEzMTA4MCwKCQkJCQkib3AiOiAiU0NNUF9D
TVBfRVEiCgkJCQl9CgkJCV0KCQl9LAoJCXsKCQkJIm5hbWVzIjogWwoJCQkJInBlcnNvbmFsaXR5
IgoJCQldLAoJCQkiYWN0aW9uIjogIlNDTVBfQUNUX0FMTE9XIiwKCQkJImFyZ3MiOiBbCgkJCQl7
CgkJCQkJImluZGV4IjogMCwKCQkJCQkidmFsdWUiOiA0Mjk0OTY3Mjk1LAoJCQkJCSJvcCI6ICJT
Q01QX0NNUF9FUSIKCQkJCX0KCQkJXQoJCX0sCgkJewoJCQkibmFtZXMiOiBbCgkJCQkic3luY19m
aWxlX3JhbmdlMiIsCgkJCQkic3dhcGNvbnRleHQiCgkJCV0sCgkJCSJhY3Rpb24iOiAiU0NNUF9B
Q1RfQUxMT1ciLAoJCQkiaW5jbHVkZXMiOiB7CgkJCQkiYXJjaGVzIjogWwoJCQkJCSJwcGM2NGxl
IgoJCQkJXQoJCQl9CgkJfSwKCQl7CgkJCSJuYW1lcyI6IFsKCQkJCSJhcm1fZmFkdmlzZTY0XzY0
IiwKCQkJCSJhcm1fc3luY19maWxlX3JhbmdlIiwKCQkJCSJzeW5jX2ZpbGVfcmFuZ2UyIiwKCQkJ
CSJicmVha3BvaW50IiwKCQkJCSJjYWNoZWZsdXNoIiwKCQkJCSJzZXRfdGxzIgoJCQldLAoJCQki
YWN0aW9uIjogIlNDTVBfQUNUX0FMTE9XIiwKCQkJImluY2x1ZGVzIjogewoJCQkJImFyY2hlcyI6
IFsKCQkJCQkiYXJtIiwKCQkJCQkiYXJtNjQiCgkJCQldCgkJCX0KCQl9LAoJCXsKCQkJIm5hbWVz
IjogWwoJCQkJImFyY2hfcHJjdGwiCgkJCV0sCgkJCSJhY3Rpb24iOiAiU0NNUF9BQ1RfQUxMT1ci
LAoJCQkiaW5jbHVkZXMiOiB7CgkJCQkiYXJjaGVzIjogWwoJCQkJCSJhbWQ2NCIsCgkJCQkJIngz
MiIKCQkJCV0KCQkJfQoJCX0sCgkJewoJCQkibmFtZXMiOiBbCgkJCQkibW9kaWZ5X2xkdCIKCQkJ
XSwKCQkJImFjdGlvbiI6ICJTQ01QX0FDVF9BTExPVyIsCgkJCSJpbmNsdWRlcyI6IHsKCQkJCSJh
cmNoZXMiOiBbCgkJCQkJImFtZDY0IiwKCQkJCQkieDMyIiwKCQkJCQkieDg2IgoJCQkJXQoJCQl9
CgkJfSwKCQl7CgkJCSJuYW1lcyI6IFsKCQkJCSJzMzkwX3BjaV9tbWlvX3JlYWQiLAoJCQkJInMz
OTBfcGNpX21taW9fd3JpdGUiLAoJCQkJInMzOTBfcnVudGltZV9pbnN0ciIKCQkJXSwKCQkJImFj
dGlvbiI6ICJTQ01QX0FDVF9BTExPVyIsCgkJCSJpbmNsdWRlcyI6IHsKCQkJCSJhcmNoZXMiOiBb
CgkJCQkJInMzOTAiLAoJCQkJCSJzMzkweCIKCQkJCV0KCQkJfQoJCX0sCgkJewoJCQkibmFtZXMi
OiBbCgkJCQkicmlzY3ZfZmx1c2hfaWNhY2hlIgoJCQldLAoJCQkiYWN0aW9uIjogIlNDTVBfQUNU
X0FMTE9XIiwKCQkJImluY2x1ZGVzIjogewoJCQkJImFyY2hlcyI6IFsKCQkJCQkicmlzY3Y2NCIK
CQkJCV0KCQkJfQoJCX0sCgkJewoJCQkibmFtZXMiOiBbCgkJCQkib3Blbl9ieV9oYW5kbGVfYXQi
CgkJCV0sCgkJCSJhY3Rpb24iOiAiU0NNUF9BQ1RfQUxMT1ciLAoJCQkiaW5jbHVkZXMiOiB7CgkJ
CQkiY2FwcyI6IFsKCQkJCQkiQ0FQX0RBQ19SRUFEX1NFQVJDSCIKCQkJCV0KCQkJfQoJCX0sCgkJ
ewoJCQkibmFtZXMiOiBbCgkJCQkiYnBmIiwKCQkJCSJjbG9uZSIsCgkJCQkiY2xvbmUzIiwKCQkJ
CSJmYW5vdGlmeV9pbml0IiwKCQkJCSJmc2NvbmZpZyIsCgkJCQkiZnNtb3VudCIsCgkJCQkiZnNv
cGVuIiwKCQkJCSJmc3BpY2siLAoJCQkJImxvb2t1cF9kY29va2llIiwKCQkJCSJtb3VudF9zZXRh
dHRyIiwKCQkJCSJtb3ZlX21vdW50IiwKCQkJCSJvcGVuX3RyZWUiLAoJCQkJInBlcmZfZXZlbnRf
b3BlbiIsCgkJCQkicXVvdGFjdGwiLAoJCQkJInF1b3RhY3RsX2ZkIiwKCQkJCSJzZXRkb21haW5u
YW1lIiwKCQkJCSJzZXRob3N0bmFtZSIsCgkJCQkic2V0bnMiLAoJCQkJInN5c2xvZyIsCgkJCQki
dW1vdW50IiwKCQkJCSJ1bW91bnQyIgoJCQldLAoJCQkiYWN0aW9uIjogIlNDTVBfQUNUX0FMTE9X
IiwKCQkJImluY2x1ZGVzIjogewoJCQkJImNhcHMiOiBbCgkJCQkJIkNBUF9TWVNfQURNSU4iCgkJ
CQldCgkJCX0KCQl9LAoJCXsKCQkJIm5hbWVzIjogWwoJCQkJImNsb25lIgoJCQldLAoJCQkiYWN0
aW9uIjogIlNDTVBfQUNUX0FMTE9XIiwKCQkJImFyZ3MiOiBbCgkJCQl7CgkJCQkJImluZGV4Ijog
MCwKCQkJCQkidmFsdWUiOiAyMTE0MDYwMjg4LAoJCQkJCSJvcCI6ICJTQ01QX0NNUF9NQVNLRURf
RVEiCgkJCQl9CgkJCV0sCgkJCSJleGNsdWRlcyI6IHsKCQkJCSJjYXBzIjogWwoJCQkJCSJDQVBf
U1lTX0FETUlOIgoJCQkJXSwKCQkJCSJhcmNoZXMiOiBbCgkJCQkJInMzOTAiLAoJCQkJCSJzMzkw
eCIKCQkJCV0KCQkJfQoJCX0sCgkJewoJCQkibmFtZXMiOiBbCgkJCQkiY2xvbmUiCgkJCV0sCgkJ
CSJhY3Rpb24iOiAiU0NNUF9BQ1RfQUxMT1ciLAoJCQkiYXJncyI6IFsKCQkJCXsKCQkJCQkiaW5k
ZXgiOiAxLAoJCQkJCSJ2YWx1ZSI6IDIxMTQwNjAyODgsCgkJCQkJIm9wIjogIlNDTVBfQ01QX01B
U0tFRF9FUSIKCQkJCX0KCQkJXSwKCQkJImNvbW1lbnQiOiAiczM5MCBwYXJhbWV0ZXIgb3JkZXJp
bmcgZm9yIGNsb25lIGlzIGRpZmZlcmVudCIsCgkJCSJpbmNsdWRlcyI6IHsKCQkJCSJhcmNoZXMi
OiBbCgkJCQkJInMzOTAiLAoJCQkJCSJzMzkweCIKCQkJCV0KCQkJfSwKCQkJImV4Y2x1ZGVzIjog
ewoJCQkJImNhcHMiOiBbCgkJCQkJIkNBUF9TWVNfQURNSU4iCgkJCQldCgkJCX0KCQl9LAoJCXsK
CQkJIm5hbWVzIjogWwoJCQkJImNsb25lMyIKCQkJXSwKCQkJImFjdGlvbiI6ICJTQ01QX0FDVF9F
UlJOTyIsCgkJCSJlcnJub1JldCI6IDM4LAoJCQkiZXhjbHVkZXMiOiB7CgkJCQkiY2FwcyI6IFsK
CQkJCQkiQ0FQX1NZU19BRE1JTiIKCQkJCV0KCQkJfQoJCX0sCgkJewoJCQkibmFtZXMiOiBbCgkJ
CQkicmVib290IgoJCQldLAoJCQkiYWN0aW9uIjogIlNDTVBfQUNUX0FMTE9XIiwKCQkJImluY2x1
ZGVzIjogewoJCQkJImNhcHMiOiBbCgkJCQkJIkNBUF9TWVNfQk9PVCIKCQkJCV0KCQkJfQoJCX0s
CgkJewoJCQkibmFtZXMiOiBbCgkJCQkiY2hyb290IgoJCQldLAoJCQkiYWN0aW9uIjogIlNDTVBf
QUNUX0FMTE9XIiwKCQkJImluY2x1ZGVzIjogewoJCQkJImNhcHMiOiBbCgkJCQkJIkNBUF9TWVNf
Q0hST09UIgoJCQkJXQoJCQl9CgkJfSwKCQl7CgkJCSJuYW1lcyI6IFsKCQkJCSJkZWxldGVfbW9k
dWxlIiwKCQkJCSJpbml0X21vZHVsZSIsCgkJCQkiZmluaXRfbW9kdWxlIgoJCQldLAoJCQkiYWN0
aW9uIjogIlNDTVBfQUNUX0FMTE9XIiwKCQkJImluY2x1ZGVzIjogewoJCQkJImNhcHMiOiBbCgkJ
CQkJIkNBUF9TWVNfTU9EVUxFIgoJCQkJXQoJCQl9CgkJfSwKCQl7CgkJCSJuYW1lcyI6IFsKCQkJ
CSJhY2N0IgoJCQldLAoJCQkiYWN0aW9uIjogIlNDTVBfQUNUX0FMTE9XIiwKCQkJImluY2x1ZGVz
IjogewoJCQkJImNhcHMiOiBbCgkJCQkJIkNBUF9TWVNfUEFDQ1QiCgkJCQldCgkJCX0KCQl9LAoJ
CXsKCQkJIm5hbWVzIjogWwoJCQkJImtjbXAiLAoJCQkJInBpZGZkX2dldGZkIiwKCQkJCSJwcm9j
ZXNzX21hZHZpc2UiLAoJCQkJInByb2Nlc3Nfdm1fcmVhZHYiLAoJCQkJInByb2Nlc3Nfdm1fd3Jp
dGV2IiwKCQkJCSJwdHJhY2UiCgkJCV0sCgkJCSJhY3Rpb24iOiAiU0NNUF9BQ1RfQUxMT1ciLAoJ
CQkiaW5jbHVkZXMiOiB7CgkJCQkiY2FwcyI6IFsKCQkJCQkiQ0FQX1NZU19QVFJBQ0UiCgkJCQld
CgkJCX0KCQl9LAoJCXsKCQkJIm5hbWVzIjogWwoJCQkJImlvcGwiLAoJCQkJImlvcGVybSIKCQkJ
XSwKCQkJImFjdGlvbiI6ICJTQ01QX0FDVF9BTExPVyIsCgkJCSJpbmNsdWRlcyI6IHsKCQkJCSJj
YXBzIjogWwoJCQkJCSJDQVBfU1lTX1JBV0lPIgoJCQkJXQoJCQl9CgkJfSwKCQl7CgkJCSJuYW1l
cyI6IFsKCQkJCSJzZXR0aW1lb2ZkYXkiLAoJCQkJInN0aW1lIiwKCQkJCSJjbG9ja19zZXR0aW1l
IiwKCQkJCSJjbG9ja19zZXR0aW1lNjQiCgkJCV0sCgkJCSJhY3Rpb24iOiAiU0NNUF9BQ1RfQUxM
T1ciLAoJCQkiaW5jbHVkZXMiOiB7CgkJCQkiY2FwcyI6IFsKCQkJCQkiQ0FQX1NZU19USU1FIgoJ
CQkJXQoJCQl9CgkJfSwKCQl7CgkJCSJuYW1lcyI6IFsKCQkJCSJ2aGFuZ3VwIgoJCQldLAoJCQki
YWN0aW9uIjogIlNDTVBfQUNUX0FMTE9XIiwKCQkJImluY2x1ZGVzIjogewoJCQkJImNhcHMiOiBb
CgkJCQkJIkNBUF9TWVNfVFRZX0NPTkZJRyIKCQkJCV0KCQkJfQoJCX0sCgkJewoJCQkibmFtZXMi
OiBbCgkJCQkiZ2V0X21lbXBvbGljeSIsCgkJCQkibWJpbmQiLAoJCQkJInNldF9tZW1wb2xpY3ki
CgkJCV0sCgkJCSJhY3Rpb24iOiAiU0NNUF9BQ1RfQUxMT1ciLAoJCQkiaW5jbHVkZXMiOiB7CgkJ
CQkiY2FwcyI6IFsKCQkJCQkiQ0FQX1NZU19OSUNFIgoJCQkJXQoJCQl9CgkJfSwKCQl7CgkJCSJu
YW1lcyI6IFsKCQkJCSJzeXNsb2ciCgkJCV0sCgkJCSJhY3Rpb24iOiAiU0NNUF9BQ1RfQUxMT1ci
LAoJCQkiaW5jbHVkZXMiOiB7CgkJCQkiY2FwcyI6IFsKCQkJCQkiQ0FQX1NZU0xPRyIKCQkJCV0K
CQkJfQoJCX0sCgkJewoJCQkibmFtZXMiOiBbCgkJCQkiYnBmIgoJCQldLAoJCQkiYWN0aW9uIjog
IlNDTVBfQUNUX0FMTE9XIiwKCQkJImluY2x1ZGVzIjogewoJCQkJImNhcHMiOiBbCgkJCQkJIkNB
UF9CUEYiCgkJCQldCgkJCX0KCQl9LAoJCXsKCQkJIm5hbWVzIjogWwoJCQkJInBlcmZfZXZlbnRf
b3BlbiIKCQkJXSwKCQkJImFjdGlvbiI6ICJTQ01QX0FDVF9BTExPVyIsCgkJCSJpbmNsdWRlcyI6
IHsKCQkJCSJjYXBzIjogWwoJCQkJCSJDQVBfUEVSRk1PTiIKCQkJCV0KCQkJfQoJCX0KCV0KfQo=
"""

#: docker-seccomp.json contents (bytes), decoded from the embedded base64.
SECCOMP_BYTES = base64.b64decode("".join(_SECCOMP_B64_WRAPPED.split()))

#: Special characters allowed in generated passwords.  Restricted to the chars
#: that need no escaping in cmd, bash, JSON and YAML (single-quoted) contexts -
#: so the same value is safe in a vault record, a docker-compose env and a shell.
#: A special char is required to satisfy enterprise password-complexity policy.
SAFE_SPECIAL_CHARACTERS = "-._"

#: Base name for the generated compose file.
COMPOSE_FILENAME = "docker-compose.yaml"
#: Seccomp filename referenced by the gateway ``security_opt``.
SECCOMP_FILENAME = "docker-seccomp.json"


def compute_network_id(project_name: str) -> str:
    """Derive the docker network id from the project name.

    Matches the Web Vault ``ContentWizardProcessing`` rule so the PAM
    configuration ``networkId`` and the generated compose network name agree.
    """
    return (project_name or "").replace(" ", "_")[:10] or "pam-net"


def compose_project_name(project_name: str) -> str:
    """Derive a docker-compose project name (top-level ``name:``) from the project.

    Compose requires lowercase ``[a-z0-9][a-z0-9_-]*``; without an explicit name it
    defaults to the output directory (e.g. ``tmp``).  We set it from ``--name`` so
    Docker Desktop shows the project meaningfully.
    """
    s = re.sub(r"[^a-z0-9_-]+", "-", (project_name or "").lower()).strip("-_")
    return s or "playground"


# =====================================================================
# 2. Credentials
# =====================================================================

def _generate_password() -> str:
    """Generate a 20-char password: 4 symbols, 4 digits, 4 caps, 4 lower.

    Matches the ``pwd_complexity="20,4,4,4,4"`` used for rotation, but the symbol
    set is restricted to :data:`SAFE_SPECIAL_CHARACTERS` (``-._``) so the value
    never needs escaping in cmd/bash/JSON/YAML.  Including a symbol satisfies
    enterprise password-complexity policy; the mix also satisfies SQL Server
    complexity (>=3 of upper/lower/digit/symbol).
    """
    return KeeperPasswordGenerator(
        length=20, symbols=4, digits=4, caps=4, lower=4,
        special_characters=SAFE_SPECIAL_CHARACTERS).generate()


#: A generated secret is "safe" when it needs no escaping in cmd/bash/JSON/YAML.
_SAFE_SECRET_RE = re.compile(r"^[A-Za-z0-9" + re.escape(SAFE_SPECIAL_CHARACTERS) + r"]+$")

# Substrings identifying the expected, benign log noise emitted by the record-add
# path (enforcement.py password-complexity + breachwatch.py) when a record uses a
# KNOWN weak/non-compliant documentary credential (image-fixed OpenLDAP demo
# users).  Suppressed only around those records - generated passwords are
# pre-validated and random, so they never trip these.
_EXPECTED_NOISE_MARKERS = (
    "Passphrase must", "Passphrase cannot", "Passphrase contains",
    "passphrase word must", "Password must", "complexity policy",
    "password policy", "High-Risk password detected",
)


class _ExpectedNoiseFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:  # False drops the record
        try:
            msg = record.getMessage()
        except Exception:  # pragma: no cover - defensive
            return True
        return not any(marker in msg for marker in _EXPECTED_NOISE_MARKERS)


@contextlib.contextmanager
def _suppress_expected_warnings():
    """Drop expected complexity/BreachWatch noise for the duration of the block.

    Installed on the root logger and its handlers so it catches the messages
    regardless of which logger or level emits them.  Used only when creating
    records with intentionally weak, image-fixed documentary credentials
    (see _create_openldap_records).
    """
    filt = _ExpectedNoiseFilter()
    root = logging.getLogger()
    # Filter on the root logger (catches module-level logging.warning calls) and
    # on its handlers (catches records propagated from child loggers).
    targets = [root, *root.handlers]
    for t in targets:
        t.addFilter(filt)
    try:
        yield
    finally:
        for t in targets:
            t.removeFilter(filt)


def _is_safe_secret(value: str) -> bool:
    return bool(value) and bool(_SAFE_SECRET_RE.match(value))


def _generate_policy_password(policy: dict) -> str:
    """Generate a random password satisfying the policy's password (not passphrase) rules.

    Mirrors the Web Vault (``getPasswordRules.ts`` + ``generateKeeperPassword``):
    honor each per-class minimum and the policy's allowed special-character set.
    Passphrase is only the Vault's *fallback* when a random password fails the
    rules, so a random password built to the rules always passes the primary
    branch - no passphrase needed.  The special set prefers the shell/YAML-safe
    subset (``-._``) when the policy allows it, else uses the policy's set (which
    still round-trips through single-quoted YAML and JSON).
    """
    from ...enforcement import _coerce_int

    def _req(use_key: str, min_key: str) -> int:
        if not policy.get(use_key):
            return 0
        n = _coerce_int(policy.get(min_key))
        return n if (isinstance(n, int) and n > 0) else 1

    # Keep a solid baseline mix (helps service complexity, e.g. SQL Server) while
    # never going below what the policy demands.
    lower = max(_req("lower-use", "lower-min"), 2)
    upper = max(_req("upper-use", "upper-min"), 2)
    digit = max(_req("digit-use", "digit-min"), 2)
    special = _req("special-use", "special-min")

    if special > 0:
        allowed = policy.get("special") or ""
        if allowed:
            # The validator counts only chars in the policy's special set.
            safe = "".join(ch for ch in SAFE_SPECIAL_CHARACTERS if ch in allowed)
            specials = safe or allowed  # prefer safe chars, else the policy's set
        else:
            specials = SAFE_SPECIAL_CHARACTERS  # any non-alnum counts -> use safe
    else:
        specials = SAFE_SPECIAL_CHARACTERS
        special = 1  # include one safe special: harmless and strengthens the password

    length = _coerce_int(policy.get("length")) or 0
    length = max(length, DEFAULT_PASSWORD_LENGTH, lower + upper + digit + special)

    return KeeperPasswordGenerator(
        length=length, symbols=special, digits=digit, caps=upper, lower=lower,
        special_characters=specials).generate()


def _build_password_factory(params) -> Callable[[], str]:
    """Return a zero-arg secret generator honoring the enterprise password policy.

    With no policy, yields a shell/YAML-safe random password.  With a policy,
    yields a random password built to satisfy the policy's password rules
    (see :func:`_generate_policy_password`), re-validated with a small retry.
    """
    try:
        from ...enforcement import PasswordComplexityEnforcer
        policy = PasswordComplexityEnforcer.get_policy(params)
    except Exception as e:  # pragma: no cover - defensive
        logging.debug("Could not read password-complexity policy: %s", e)
        return _generate_password

    if not policy:
        return _generate_password

    from ...enforcement import PasswordComplexityEnforcer

    def _gen() -> str:
        pw = _generate_policy_password(policy)
        for _ in range(5):
            if not PasswordComplexityEnforcer.validate_password(pw, policy):
                return pw
            pw = _generate_policy_password(policy)
        logging.debug("Generated password still failed policy after retries; using last attempt")
        return pw

    return _gen


def _generate_ssh_keypair(comment: str = "linuxuser@local"):
    """Generate an RSA-2048 keypair (OpenSSH PEM private, OpenSSH public).

    RSA-2048 to match the Web Vault sample (not Ed25519).  Returns
    ``(private_openssh_pem, public_openssh_line)``.
    """
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.OpenSSH,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")
    public_line = key.public_key().public_bytes(
        encoding=serialization.Encoding.OpenSSH,
        format=serialization.PublicFormat.OpenSSH,
    ).decode("utf-8")
    if comment:
        public_line = f"{public_line} {comment}"
    return private_pem, public_line


# Default DAG options for playground machines/DBs — matches sequential
# ``_enable_connection`` + ``_allow_resource`` (connections must be on for Launch).
_DEFAULT_PAM_OPTIONS = {
    "rotation": "on",
    "connections": "on",
    "tunneling": "on",
    "graphical_session_recording": "on",
    "text_session_recording": "on",
    "remote_browser_isolation": "off",
}


class PlaygroundCredentials:
    """All secrets for one ``--sample-data`` run, generated once up front.

    Randomized per run (see the plan table).  ``server-openldap-1`` is baked
    into the ``rroemhild/test-openldap`` image and ``server-telnet`` has no auth,
    so those creds are fixed/documentary, not generated.
    """

    # OpenLDAP demo directory (image rroemhild/test-openldap - fixed creds).
    OPENLDAP_DOMAIN = "planetexpress.com"
    OPENLDAP_ADMIN_DN = "cn=admin,dc=planetexpress,dc=com"
    OPENLDAP_ADMIN_PASSWORD = "GoodNewsEveryone"
    # (login, password, distinguished name) for the fixed demo users.
    OPENLDAP_DEMO_USERS = [
        ("professor", "professor", "cn=Hubert J. Farnsworth,ou=people,dc=planetexpress,dc=com"),
        ("fry", "fry", "cn=Philip J. Fry,ou=people,dc=planetexpress,dc=com"),
        ("zoidberg", "zoidberg", "cn=John A. Zoidberg,ou=people,dc=planetexpress,dc=com"),
        ("hermes", "hermes", "cn=Hermes Conrad,ou=people,dc=planetexpress,dc=com"),
        ("leela", "leela", "cn=Turanga Leela,ou=people,dc=planetexpress,dc=com"),
        ("bender", "bender", "cn=Bender Bending Rodriguez,ou=people,dc=planetexpress,dc=com"),
        ("amy", "amy", "cn=Amy Wong+sn=Kroker,ou=people,dc=planetexpress,dc=com"),
    ]

    def __init__(self, password_factory: Optional[Callable[[], str]] = None):
        # `password_factory` yields one policy-compliant, shell/YAML-safe secret
        # per call (see _build_password_factory). Defaults to a safe random password.
        gen = password_factory or _generate_password
        # MySQL (db-mysql-1)
        self.mysql_root_password = gen()
        self.mysql_user_password = gen()
        # PostgreSQL (db-postgres-1)
        self.postgres_password = gen()
        # MariaDB (db-mariadb-1)
        self.mariadb_root_password = gen()
        self.mariadb_user_password = gen()
        # Microsoft SQL Server (db-mssql)
        self.mssql_sa_password = gen()
        # MongoDB (db-mongo)
        self.mongo_root_password = gen()
        self.mongo_user_password = gen()
        # SSH password (server-ssh-with-pwd-1)
        self.ssh_password = gen()
        # SSH key (server-ssh-with-key-1) — private key is primary auth; also
        # store a strong vault password so pamUser validation stays quiet.
        self.ssh_private_key, self.ssh_public_key = _generate_ssh_keypair()
        self.ssh_key_user_password = gen()
        # VNC (server-vnc)
        self.vnc_password = gen()        # RDP (server-rdp)
        self.rdp_user_password = gen()
        self.rdp_root_password = gen()
        # Telnet (server-telnet) - compose has no auth; used for rotation testing only
        self.telnet_password = gen()


# =====================================================================
# 3. Session
# =====================================================================

class PlaygroundSession:
    """Orchestrates the sample-data flow: credentials, records, compose, output."""

    def __init__(self, params, project: dict):
        self.params = params
        self.project = project
        self.project_name: str = project["options"]["project_name"]
        self.network_id: str = compute_network_id(self.project_name)
        self.users_folder_uid: str = project["folders"]["users_folder_uid"]
        self.resources_folder_uid: str = project["folders"]["resources_folder_uid"]
        self.pam_config_uid: str = project["pam_config"]["pam_config_uid"]
        # Generate credentials compliant with the enterprise password policy
        # (passphrase or random), all shell/YAML-safe.
        self.creds = PlaygroundCredentials(_build_password_factory(params))
        self.resources: List[Any] = []

    # ---- record creation (batched) --------------------------------------

    def create_all_records(self) -> bool:
        """Build playground Pam* objects and create them via BatchPamImportEngine."""
        self.resources = self.build_resources()
        assign_uids(self.resources, only_new=False)
        self._resolve_refs()

        engine = BatchPamImportEngine(
            self.params, self.project,
            users=[],
            resources=self.resources,
            users_folder_uid=self.users_folder_uid,
            resources_folder_uid=self.resources_folder_uid,
            pam_cfg_uid=self.pam_config_uid,
            extend_mode=False,
        )
        # OpenLDAP demo passwords are intentionally weak (image-fixed); suppress
        # the expected policy/BreachWatch noise the sequential path also muted.
        with _suppress_expected_warnings():
            ok = engine.run()
        if not ok:
            logging.error(f"{bcolors.FAIL}Playground sample-data batch import aborted.{bcolors.ENDC}")
            return False
        api.sync_down(self.params)
        return True

    def simulate(self) -> dict:
        """Dry-run batch plan for playground resources (no vault writes)."""
        self.resources = self.build_resources()
        assign_uids(self.resources, only_new=False)
        self._resolve_refs()
        engine = BatchPamImportEngine(
            self.params, self.project,
            users=[],
            resources=self.resources,
            users_folder_uid=self.users_folder_uid,
            resources_folder_uid=self.resources_folder_uid,
            pam_cfg_uid=self.pam_config_uid,
            extend_mode=False,
        )
        return engine.simulate()

    def _resolve_refs(self) -> None:
        """Resolve administrative/launch credentials / rotation resourceUid like process_data."""
        for mach in self.resources:
            if isinstance(mach, PamRemoteBrowserObject):
                continue
            admin_cred = get_admin_credential(mach)
            if admin_cred:
                matches = find_user(mach, [], admin_cred)
                if len(matches) != 1:
                    logging.warning(
                        f"{bcolors.WARNING}{len(matches)} matches for "
                        f"administrative_credentials '{admin_cred}' in {mach.title}.{bcolors.ENDC}",
                    )
                if matches:
                    set_user_record_uid(mach, matches[0].uid, False)
            launch_cred = get_launch_credential(mach)
            if launch_cred:
                matches = find_user(mach, [], launch_cred)
                if len(matches) != 1:
                    logging.warning(
                        f"{bcolors.WARNING}{len(matches)} matches for "
                        f"launch_credentials '{launch_cred}' in {mach.title}.{bcolors.ENDC}",
                    )
                if matches:
                    set_launch_record_uid(mach, matches[0].uid)
            for usr in getattr(mach, "users", None) or []:
                if (usr and getattr(usr, "rotation_settings", None)
                        and usr.rotation_settings
                        and getattr(usr.rotation_settings, "rotation", None) == "general"):
                    usr.rotation_settings.resourceUid = mach.uid
            resolve_script_creds(mach, [], self.resources)

    def _title(self, suffix: str) -> str:
        # Record titles are NOT project-prefixed - the enclosing folders
        # (e.g. "<project> - Resources"/"- Users") already provide that context.
        return suffix

    def _user(
        self,
        title: str,
        login: str,
        *,
        password: Optional[str] = None,
        private_key: Optional[str] = None,
        distinguished_name: Optional[str] = None,
        notes: Optional[str] = None,
        rotate: bool = False,
    ) -> dict:
        data: Dict[str, Any] = {"type": "pamUser", "title": self._title(title), "login": login}
        if private_key is not None:
            data["private_pem_key"] = private_key
        if password is not None:
            data["password"] = password
        elif private_key is not None:
            # pamUser validation requires a password field; key remains primary SSH auth.
            data["password"] = self.creds.ssh_key_user_password
        if distinguished_name:
            data["distinguished_name"] = distinguished_name
        if notes:
            data["notes"] = notes
        if rotate:
            data["rotation_settings"] = dict(_ON_DEMAND_ROTATION)
        return data

    def _conn(
        self,
        protocol: str,
        admin_title: str,
        *,
        database: Optional[str] = None,
        extra: Optional[dict] = None,
        port_forward: bool = True,
        options: Optional[dict] = None,
    ) -> dict:
        connection: Dict[str, Any] = {
            "protocol": protocol,
            "administrative_credentials": admin_title,
            # Same user as admin — vault Launch Credential / connections need this
            # (old sequential path passed admin into PAMTunnelEdit as connect user).
            "launch_credentials": admin_title,
        }
        if database is not None:
            connection["database"] = database
        if extra:
            connection.update(extra)
        pam_settings: Dict[str, Any] = {
            "connection": connection,
            "port_forward": {"reuse_port": True} if port_forward else {},
            "options": {**_DEFAULT_PAM_OPTIONS, **(options or {})},
        }
        return pam_settings

    def build_resources(self) -> List[Any]:
        """Materialize playground services as Pam*Object trees (no vault writes)."""
        c = self.creds
        rotation_params = PamRotationParams(configUid=self.pam_config_uid, profiles={})
        resources: List[Any] = []

        def add_db(data: dict):
            resources.append(PamDatabaseObject.load(data, rotation_params))

        def add_machine(data: dict):
            resources.append(PamMachineObject.load(data, rotation_params))

        def add_dir(data: dict):
            resources.append(PamDirectoryObject.load(data, rotation_params))

        def add_rbi(data: dict):
            resources.append(PamRemoteBrowserObject.load(data, rotation_params))

        # MySQL
        add_db({
            "type": "pamDatabase",
            "title": self._title("MySQL Database"),
            "host": "db-mysql-1",
            "port": "3306",
            "database_type": "mysql",
            "pam_settings": self._conn("mysql", "MySQL Admin User", database="salesdb"),
            "users": [
                # Admin: credential only (is_admin+launch, no belongs_to / no Rotate Now).
                self._user("MySQL Admin User", "root", password=c.mysql_root_password),
                self._user("MySQL Rotation User", "sqluser", password=c.mysql_user_password, rotate=True),
            ],
        })

        # SSH password
        add_machine({
            "type": "pamMachine",
            "title": self._title("SSH Machine with Password Access"),
            "host": "server-ssh-with-pwd-1",
            "port": "2222",
            "pam_settings": self._conn("ssh", "SSH Admin with Password"),
            "users": [
                self._user("SSH Admin with Password", "linuxuser",
                           password=c.ssh_password, rotate=True),
            ],
        })

        # SSH key
        add_machine({
            "type": "pamMachine",
            "title": self._title("SSH Machine with Private Key Access"),
            "host": "server-ssh-with-key-1",
            "port": "2222",
            "pam_settings": self._conn("ssh", "SSH Admin with Private Key"),
            "users": [
                self._user("SSH Admin with Private Key", "linuxuser",
                           private_key=c.ssh_private_key,
                           password=c.ssh_key_user_password,
                           rotate=True),
            ],
        })
        # VNC — admin credential/launch only; no rotation (Web Vault parity)
        add_machine({
            "type": "pamMachine",
            "title": self._title("VNC Machine"),
            "host": "server-vnc",
            "port": "5901",
            "pam_settings": self._conn("vnc", "VNC Admin"),
            "users": [
                self._user("VNC Admin", "vncuser", password=c.vnc_password),
            ],
        })

        # RDP — Admin is credential/launch only; RDP User is vault-only (not
        # linked onto the machine). Neither is set up for rotation.
        add_machine({
            "type": "pamMachine",
            "title": self._title("RDP Machine"),
            "host": "server-rdp",
            "port": "3389",
            "pam_settings": self._conn(
                "rdp", "RDP Admin",
                extra={"security": "any", "ignore_server_cert": True},
            ),
            "users": [
                self._user("RDP User", "linuxuser", password=c.rdp_user_password),
                self._user("RDP Admin", "root", password=c.rdp_root_password),
            ],
        })

        # RBI
        add_rbi({
            "type": "pamRemoteBrowser",
            "title": self._title("Bing Remote Browser"),
            "url": "https://bing.com",
            "pam_settings": {
                "connection": {
                    "protocol": "http",
                    "allow_url_manipulation": True,
                    "allow_supply_user": True,
                    "clipboard_buffer_size": "10mb",
                    "accept_language": "en-US,en;q=0.9",
                    "suppress_js_dialogs": True,
                },
                "options": {
                    "rotation": "off",
                    "connections": "on",
                    "tunneling": "off",
                    "remote_browser_isolation": "on",
                    "graphical_session_recording": "on",
                    "text_session_recording": "off",
                },
            },
        })

        # PostgreSQL
        add_db({
            "type": "pamDatabase",
            "title": self._title("PostgreSQL Database"),
            "host": "db-postgres-1",
            "port": "5432",
            "database_type": "postgresql",
            "pam_settings": self._conn("postgresql", "PostgreSQL Admin User", database="postgres"),
            "users": [
                self._user("PostgreSQL Admin User", "postgres",
                           password=c.postgres_password, rotate=True),
            ],
        })

        # MariaDB
        add_db({
            "type": "pamDatabase",
            "title": self._title("MariaDB Database"),
            "host": "db-mariadb-1",
            "port": "3306",
            "database_type": "mariadb",
            "pam_settings": self._conn("mysql", "MariaDB Admin User", database="mydb"),
            "users": [
                # Admin credential only (no rotate) — matches Web Vault admin ACL.
                self._user("MariaDB Admin User", "root", password=c.mariadb_root_password),
                self._user("MariaDB Rotation User", "max",
                           password=c.mariadb_user_password, rotate=True),
            ],
        })

        # MSSQL
        add_db({
            "type": "pamDatabase",
            "title": self._title("Microsoft SQL Server Database"),
            "host": "db-mssql",
            "port": "1433",
            "database_type": "mssql",
            "pam_settings": self._conn("sql-server", "Microsoft SQL Server Admin User", database="master"),
            "users": [
                self._user("Microsoft SQL Server Admin User", "sa",
                           password=c.mssql_sa_password, rotate=True),
            ],
        })

        # MongoDB intentionally omitted — see origin comment on ConversationType.

        # Telnet — nyancat image has no auth; admin is launch/credential only
        # (rotation is not possible against this backend).
        add_machine({
            "type": "pamMachine",
            "title": self._title("Telnet Machine"),
            "host": "server-telnet",
            "port": "23",
            "pam_settings": self._conn("telnet", "Telnet Admin"),
            "users": [
                self._user("Telnet Admin", "user", password=c.telnet_password),
            ],
        })

        # OpenLDAP
        # Admin is directory bind credential only — Gateway cannot rotate the
        # image root DN (cn=admin,dc=… has no ou=; kdnrm openldap_req_ou).
        # Demo users under ou=people are the rotation targets.
        ldap_users = [
            self._user(
                "OpenLDAP Admin", c.OPENLDAP_ADMIN_DN, password=c.OPENLDAP_ADMIN_PASSWORD,
                notes=f"OpenLDAP directory admin (image-fixed; not rotatable). "
                      f"Domain: {c.OPENLDAP_DOMAIN}",
                distinguished_name=c.OPENLDAP_ADMIN_DN,
            ),
        ]
        for login, password, dn in c.OPENLDAP_DEMO_USERS:
            ldap_users.append(self._user(
                f"OpenLDAP User ({login})", login, password=password,
                notes="OpenLDAP demo user. Initial password from image; "
                      "rotated via cn=admin.",
                distinguished_name=dn,
                rotate=True,
            ))
        add_dir({
            "type": "pamDirectory",
            "title": self._title("OpenLDAP Directory"),
            "host": "server-openldap-1",
            "port": "10389",
            "directory_type": "openldap",
            "domain_name": c.OPENLDAP_DOMAIN,
            "notes": "OpenLDAP demo directory (rroemhild/test-openldap, image-fixed users).",
            # No interactive connect protocol for directories; use SSH settings shape
            # only to carry administrative_credentials into the typed loader
            # (same admin-link outcome as the sequential playground path).
            "pam_settings": self._conn(
                "ssh", "OpenLDAP Admin",
                options={
                    "rotation": "on",
                    "connections": "off",
                    "tunneling": "on",
                    "graphical_session_recording": "off",
                    "text_session_recording": "off",
                    "remote_browser_isolation": "off",
                },
            ),
            "users": ldap_users,
        })

        return resources

    # ---- compose --------------------------------------------------------

    def build_compose(self, gateway_config_b64: str) -> str:
        """Build the ``docker-compose.yaml`` text for the playground."""
        return build_compose(self.network_id, gateway_config_b64, self.creds, self.project_name)

    # ---- output ---------------------------------------------------------

    def save_compose_and_seccomp(self, compose_yaml: str) -> str:
        """Write compose + seccomp to disk and print the two-line summary."""
        return save_compose_and_seccomp(compose_yaml)


# =====================================================================
# 5. Compose
# =====================================================================

def _yq(value: Any) -> str:
    """Quote a scalar as a docker-compose value (safe for any character).

    Two independent escapes are applied:

    * ``'`` -> ``''`` - YAML single-quote escaping.  Inside single quotes every
      other character (``\\``, ``"``, backtick, ``:`` ...) is already literal.
    * ``$`` -> ``$$`` - docker-compose runs variable interpolation (``$VAR`` /
      ``${VAR}``) on parsed string values *after* YAML quoting is stripped, so a
      literal ``$`` must be doubled to reach the container unchanged.

    This makes any enterprise-policy special character round-trip correctly, so
    the value the service receives matches the value stored in the vault record.
    """
    s = "" if value is None else str(value)
    s = s.replace("$", "$$")   # docker-compose interpolation escape
    s = s.replace("'", "''")   # YAML single-quote escape
    return "'" + s + "'"


def _service_lines(name: str, body: List[str]) -> str:
    indented = "\n".join("    " + line if line else "" for line in body)
    return f"  {name}:\n{indented}\n"


def _gateway_block(network_id: str, gateway_config_b64: str) -> str:
    body = [
        "platform: linux/amd64",
        f"image: {GATEWAY_IMAGE}",
        "shm_size: 2g",
        "restart: unless-stopped",
        "deploy:",
        "  resources:",
        "    limits:",
        '      cpus: "4"',
        '      memory: "2g"',
        "security_opt:",
        f"  - seccomp:{SECCOMP_FILENAME}",
        "  - apparmor=unconfined",
        "environment:",
        '  ACCEPT_EULA: "Y"',
        # Verbose logging - this is a debugging/testing playground; makes rotation
        # and connection activity visible in `docker logs`.
        '  KEEPER_GATEWAY_LOG_LEVEL: "debug"',
        '  LOG_LEVEL: "debug"',
        f"  GATEWAY_CONFIG: {_yq(gateway_config_b64)}",
        "networks:",
        f"  - {network_id}",
        "depends_on:",
    ]
    body += [f"  - {svc}" for svc in GATEWAY_DEPENDS_ON]
    return _service_lines("keeper-gateway", body)


def _backend_block(name: str, image: str, env: List, network_id: str,
                   extra: Optional[List[str]] = None) -> str:
    body = ["platform: linux/amd64", f"image: {image}", "restart: unless-stopped"]
    if extra:
        body += extra
    if env:
        body.append("environment:")
        for key, val in env:
            body.append(f"  {key}: {_yq(val)}")
    body += ["networks:", f"  - {network_id}"]
    return _service_lines(name, body)


def _ephemeral_data_tmpfs(path: str) -> List[str]:
    """Mount DB data on tmpfs so image entrypoint always re-inits from env.

    Official DB images declare a VOLUME; Compose then keeps an anonymous volume
    across recreate. Regenerated sample-data passwords in compose/vault then
    no longer match the old data dir → ``Access denied`` / authentication failed
    (seen on db-mariadb-1 / db-postgres-1). tmpfs avoids that class of drift.

    Path must match the image VOLUME (postgres:18+ uses ``/var/lib/postgresql``,
    not the older ``/var/lib/postgresql/data``).

    Do **not** use this for ``db-mssql``: SQL Server 2022 runs as non-root
    ``mssql`` (UID 10001) and fails on a root-owned tmpfs with
    ``The system directory [/.system] could not be created`` (Access Denied).
    """
    return ["tmpfs:", f"  - {path}"]


def build_compose(network_id: str, gateway_config_b64: str, creds: PlaygroundCredentials,
                  project_name: str = "") -> str:
    """Render the full docker-compose.yaml (name + network + gateway + 11 backends)."""
    parts: List[str] = []
    parts.append(
        "# Generated by Keeper Commander `pam project import --sample-data`.\n"
        "# Credentials below are also stored as records in your Keeper vault.\n"
        "# DB data dirs (mysql/mariadb/postgres) use tmpfs so passwords always\n"
        "# match this file. MSSQL keeps the image volume (non-root mssql user\n"
        "# cannot write a root-owned tmpfs) — use `docker compose down -v` if\n"
        "# SA password drifts after regenerating sample-data.\n"
        f"name: {compose_project_name(project_name)}\n"
        "\n"
        "# Docker auto-assigns this network's subnet to avoid pool overlaps. To\n"
        f"# pin a subnet (e.g. for discovery), add an `ipam` block under {network_id}:\n"
        "#     ipam:\n"
        "#       config:\n"
        f"#         - subnet: {NETWORK_SUBNET}\n"
        "networks:\n"
        f"  {network_id}:\n"
        "    driver: bridge\n"
        "\n"
        "services:\n"
    )

    parts.append(_gateway_block(network_id, gateway_config_b64))

    parts.append(_backend_block("db-mysql-1", "mysql/mysql-server:8.0", [
        ("MYSQL_ROOT_HOST", "%"),
        ("MYSQL_ROOT_PASSWORD", creds.mysql_root_password),
        ("MYSQL_DATABASE", "salesdb"),
        ("MYSQL_USER", "sqluser"),
        ("MYSQL_PASSWORD", creds.mysql_user_password),
    ], network_id, extra=_ephemeral_data_tmpfs("/var/lib/mysql")))

    parts.append(_backend_block("db-postgres-1", "postgres", [
        ("POSTGRES_DB", "postgres"),
        ("POSTGRES_USER", "postgres"),
        ("POSTGRES_PASSWORD", creds.postgres_password),
    ], network_id, extra=_ephemeral_data_tmpfs("/var/lib/postgresql")))

    parts.append(_backend_block("db-mariadb-1", "mariadb:10.8", [
        ("MARIADB_ROOT_HOST", "%"),
        ("MARIADB_ROOT_PASSWORD", creds.mariadb_root_password),
        ("MARIADB_DATABASE", "mydb"),
        ("MARIADB_USER", "max"),
        ("MARIADB_PASSWORD", creds.mariadb_user_password),
    ], network_id, extra=_ephemeral_data_tmpfs("/var/lib/mysql") + [
        "ports:",
        "  - mode: host",
        "    target: 3306",
        "    published: 33306",
    ]))

    parts.append(_backend_block("db-mssql", "mcr.microsoft.com/mssql/server:2022-latest", [
        ("MSSQL_SA_PASSWORD", creds.mssql_sa_password),
        ("MSSQL_PID", "Developer"),
        ("ACCEPT_EULA", "Y"),
    ], network_id))

    # db-mongo is disabled together with the MongoDB record (see
    # _create_mongodb_records) - no vault record would manage this container until
    # the gateway supports the "mongodb" WebRTC ConversationType. Re-enable this
    # block, the record call, and the GATEWAY_DEPENDS_ON entry together.
    # parts.append(_backend_block("db-mongo", "bitnami/mongodb:latest", [
    #     ("MONGO_INITDB_ROOT_USERNAME", "root"),
    #     ("MONGO_INITDB_ROOT_PASSWORD", creds.mongo_root_password),
    #     ("MONGO_INITDB_DATABASE", "mydatabase"),
    #     ("MONGO_INITDB_USERNAME", "user1"),
    #     ("MONGO_INITDB_PASSWORD", creds.mongo_user_password),
    #     ("EXPERIMENTAL_DOCKER_DESKTOP_FORCE_QEMU", "1"),
    # ], network_id))

    parts.append(_backend_block("server-ssh-with-pwd-1", "lscr.io/linuxserver/openssh-server", [
        ("PUID", "1000"),
        ("PGID", "1000"),
        ("TZ", "America/Los_Angeles"),
        ("SUDO_ACCESS", "true"),
        ("PASSWORD_ACCESS", "true"),
        ("USER_NAME", "linuxuser"),
        ("USER_PASSWORD", creds.ssh_password),
    ], network_id))

    parts.append(_backend_block("server-ssh-with-key-1", "lscr.io/linuxserver/openssh-server", [
        ("PUID", "1000"),
        ("PGID", "1000"),
        ("TZ", "America/Los_Angeles"),
        ("PUBLIC_KEY", creds.ssh_public_key),
        ("SUDO_ACCESS", "true"),
        ("USER_NAME", "linuxuser"),
        ("PASSWORD_ACCESS", "false"),
    ], network_id))

    parts.append(_backend_block("server-vnc", "keeper/playground-vnc-xfce:latest", [
        ("VNC_PW", creds.vnc_password),
        ("VNC_RESOLUTION", "1010x760"),
    ], network_id))

    parts.append(_backend_block("server-rdp", "keeper/playground-rdp-xfce:latest", [
        ("USER", "linuxuser"),
        ("PASSWORD", creds.rdp_user_password),
        ("ROOT_PASSWORD", creds.rdp_root_password),
    ], network_id, extra=[
        "shm_size: 2g",
        "security_opt:",
        "  - seccomp:unconfined",
        "deploy:",
        "  resources:",
        "    limits:",
        '      cpus: "4"',
        '      memory: "2g"',
    ]))

    # server-telnet: nyancat, no auth / no env.
    parts.append(_backend_block("server-telnet", "ddhhz/nyancat-server", [], network_id))

    # server-openldap-1: rroemhild/test-openldap, image-fixed creds / no env.
    parts.append(_backend_block("server-openldap-1", "rroemhild/test-openldap", [], network_id))

    return "".join(parts)


# =====================================================================
# 6. Output
# =====================================================================

def _unique_compose_path(directory: str) -> str:
    """Pick a non-colliding compose path in ``directory``."""
    candidate = os.path.join(directory, COMPOSE_FILENAME)
    if not os.path.exists(candidate):
        return candidate
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    candidate = os.path.join(directory, f"docker-compose-{stamp}.yaml")
    if not os.path.exists(candidate):
        return candidate
    return os.path.join(directory, f"docker-compose-{stamp}-{token_hex(3)}.yaml")


def save_compose_and_seccomp(compose_yaml: str) -> str:
    """Write compose (collision-safe) + seccomp (skip if present); print 2 lines.

    Primary target is the current working directory; on write failure it falls
    back to the OS temp dir.  Returns the absolute compose path.
    """
    for directory in (os.getcwd(), tempfile.gettempdir()):
        try:
            compose_path = _unique_compose_path(directory)
            with open(compose_path, "w", encoding="utf-8", newline="\n") as f:
                f.write(compose_yaml)
            # seccomp lives beside the compose; write only if absent (identical
            # for every run, referenced by security_opt: seccomp:docker-seccomp.json).
            seccomp_path = os.path.join(os.path.dirname(compose_path), SECCOMP_FILENAME)
            if not os.path.exists(seccomp_path):
                with open(seccomp_path, "wb") as f:
                    f.write(SECCOMP_BYTES)
            compose_abs = os.path.abspath(compose_path)
            print(compose_abs)
            print(SECCOMP_URL)
            return compose_abs
        except OSError as e:
            logging.debug("Could not write compose to %s: %s", directory, e)
            continue
    logging.warning(f"{bcolors.FAIL}Failed to write docker-compose.yaml "
                    f"(cwd and temp dir both unwritable){bcolors.ENDC}")
    return ""
