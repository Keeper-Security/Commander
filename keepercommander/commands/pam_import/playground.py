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
    3. Session             - PlaygroundSession (creds -> records -> compose -> save)
    4. Record creators     - _create_* helpers (one per playground service)
    5. Compose             - build_compose() + per-service YAML builders
    6. Output              - save_compose_and_seccomp()

The credentials are generated once per run (no hard-coded secrets) and shared
between the vault records and the generated ``docker-compose.yaml`` so the two
always agree.  The compose template mirrors the discovery-playground repo's
``origin/main:docker-compose.yaml``.
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
from ..record_edit import RecordAddCommand as RecordEditAddCommand
from ..tunnel.port_forward.TunnelGraph import TunnelDAG
from ..tunnel.port_forward.tunnel_helpers import get_keeper_tokens
from ..tunnel_and_connections import PAMTunnelEditCommand

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

    Matches the origin/vault sample (RSA, not Ed25519).  Returns
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
        # SSH key (server-ssh-with-key-1)
        self.ssh_private_key, self.ssh_public_key = _generate_ssh_keypair()
        # VNC (server-vnc)
        self.vnc_password = gen()
        # RDP (server-rdp)
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

        # Command/DAG helpers (initialized in create_all_records).
        self._command: Optional[RecordEditAddCommand] = None
        self._pte: Optional[PAMTunnelEditCommand] = None
        self._tdag: Optional[TunnelDAG] = None

    # ---- record creation ------------------------------------------------

    def create_all_records(self):
        """Create every playground record + DAG link, matching the origin services."""
        from ..discoveryrotation import PAMCreateRecordRotationCommand
        self._rotation_cls = PAMCreateRecordRotationCommand

        self._command = RecordEditAddCommand()
        self._pte = PAMTunnelEditCommand()

        encrypted_session_token, encrypted_transmission_key, transmission_key = get_keeper_tokens(self.params)
        self._tdag = TunnelDAG(
            self.params, encrypted_session_token, encrypted_transmission_key,
            self.pam_config_uid, True, transmission_key=transmission_key)
        # Fix: rotation/connections disabled by the PAM configuration.
        self._tdag.set_resource_allowed(
            self.pam_config_uid, is_config=True, rotation=True, connections=True, tunneling=True,
            session_recording=True, typescript_recording=True, remote_browser_isolation=True)

        self._create_mysql_records()
        self._create_ssh_password_records()
        self._create_ssh_key_records()
        self._create_vnc_records()
        self._create_rdp_records()
        self._create_rbi_record()
        self._create_postgresql_records()
        self._create_mariadb_records()
        self._create_mssql_records()
        # MongoDB interactive connect is not yet wired end-to-end: the gateway's
        # WebRTC ConversationType enum (keeper-pam-webrtc-rs models.rs) has no
        # "mongodb" variant, so a KeeperDB connect fails with
        #   "'mongodb' is not a valid ConversationType"
        # even though a guacr MongoDbHandler exists (it's never reached). WV sends
        # conversationType="mongodb"+useKeeperDb=true correctly; only
        # mysql/postgresql/sql-server are routable DB conversation types today.
        # Re-enable this call + the db-mongo compose service + its GATEWAY_DEPENDS_ON
        # entry once the gateway/keeper-pam-connections adds mongodb (and the other
        # DB protocols) to ConversationType.
        # self._create_mongodb_records()
        self._create_telnet_records()
        self._create_openldap_records()

        api.sync_down(self.params)

    # ---- record-creation helpers ---------------------------------------

    def _title(self, suffix: str) -> str:
        # Record titles are NOT project-prefixed - the enclosing folders
        # (e.g. "<project> - Resources"/"- Users") already provide that context.
        return suffix

    def _add(self, record_type: str, folder_uid: str, suffix: str,
             fields: List[str], notes: Optional[str] = None,
             quiet_policy: bool = False) -> str:
        """Create a typed record via the record-add command; return its UID.

        Uses dot-notation field specs (``f.login=..``, ``c.pamSettings=$JSON:..``)
        exactly like the PAM importer (pam_import/base.py) so records are built
        from the record-type definition - no legacy "Unknown field types" noise -
        and ``force=True`` bypasses the interactive password-policy prompt.

        ``quiet_policy`` suppresses the (expected) complexity-policy and
        BreachWatch "High-Risk password" noise for records whose credentials are
        intentionally weak/fixed (image-baked OpenLDAP demo users); ``force=True``
        still creates them.
        """
        args: Dict[str, Any] = {
            "force": True, "folder": folder_uid,
            "record_type": record_type, "title": self._title(suffix),
        }
        if fields:
            args["fields"] = fields
        if notes:
            args["notes"] = notes
        if quiet_policy:
            with _suppress_expected_warnings():
                return self._command.execute(self.params, **args)
        return self._command.execute(self.params, **args)

    def _add_user(self, suffix: str, login: str, password: Optional[str] = None,
                  private_key: Optional[str] = None, notes: Optional[str] = None,
                  distinguished_name: Optional[str] = None, quiet_policy: bool = False) -> str:
        """Create a pamUser record and return its UID.

        ``distinguished_name`` is required to rotate a directory (LDAP/AD) user -
        kdnrm modifies the entry by its DN, not by the login/uid.
        """
        fields = [f"f.login={login}"]
        if private_key is not None:
            fields.append(f"f.secret.privatePEMKey={private_key}")  # password left empty
        elif password:
            fields.append(f"f.password={password}")
        if distinguished_name:
            fields.append(f"f.text.distinguishedName={distinguished_name}")
        return self._add("pamUser", self.users_folder_uid, suffix, fields, notes,
                         quiet_policy=quiet_policy)

    def _add_resource(self, record_type: str, suffix: str, *, host: Optional[str] = None,
                      port: Optional[str] = None, database_type: Optional[str] = None,
                      directory_type: Optional[str] = None, domain_name: Optional[str] = None,
                      rbi_url: Optional[str] = None, connection: Optional[dict] = None,
                      port_forward: Optional[dict] = None, notes: Optional[str] = None) -> str:
        """Create a resource record (pamMachine/pamDatabase/pamDirectory/pamRemoteBrowser).

        ``trafficEncryptionSeed`` is intentionally omitted - it is populated later
        by the tunnel/DAG step (matches pam_import/base.py).
        """
        fields: List[str] = []
        if host is not None or port is not None:
            fields.append("f.pamHostname=$JSON:" + json.dumps({"hostName": host or "", "port": port or ""}))
        if database_type:
            fields.append(f"f.databaseType={database_type}")
        if directory_type:
            fields.append(f"f.directoryType={directory_type}")
        if domain_name:
            fields.append(f"f.text.domainName={domain_name}")
        if record_type == "pamRemoteBrowser":
            if rbi_url:
                fields.append(f"rbiUrl={rbi_url}")
            if connection is not None:
                fields.append("pamRemoteBrowserSettings=$JSON:" + json.dumps({"connection": connection}))
        elif connection is not None or port_forward is not None:
            fields.append("c.pamSettings=$JSON:" + json.dumps(
                {"allowSupplyHost": False, "portForward": port_forward or {}, "connection": connection or {}}))
        return self._add(record_type, self.resources_folder_uid, suffix, fields, notes)

    def _allow_resource(self, resource_uid: str, rotation=True, connections=True, tunneling=True,
                        session_recording=True, typescript_recording=True, remote_browser_isolation=True):
        self._tdag.set_resource_allowed(
            resource_uid=resource_uid, rotation=rotation, connections=connections, tunneling=tunneling,
            session_recording=session_recording, typescript_recording=typescript_recording,
            remote_browser_isolation=remote_browser_isolation)

    def _enable_connection(self, resource_uid: str, admin_user_uid: Optional[str] = None,
                           enable_connections=True, enable_tunneling=True):
        self._tdag.link_resource_to_config(resource_uid)
        kwargs = dict(record=resource_uid, config=self.pam_config_uid,
                      enable_connections=enable_connections, enable_tunneling=enable_tunneling, silent=True)
        if admin_user_uid:
            kwargs["admin"] = admin_user_uid
        self._pte.execute(self.params, **kwargs)

    def _rotate(self, record_uid: str, admin_user_uid: str, resource_uid: str):
        # PAMCreateRecordRotationCommand resolves the record/admin/resource from
        # the local cache; records are created with sync deferred (sync_data), so
        # sync first or the rotation SETTINGS silently fail to persist (the record
        # would then show RRS_NO_ROTATION even though the DAG rotation flag is set).
        api.sync_down(self.params)
        self._rotation_cls().execute(
            self.params, record_name=record_uid, admin=admin_user_uid,
            config=self.pam_config_uid, resource=resource_uid,
            on_demand=True, pwd_complexity="20,4,4,4,4", enable=True, force=True, silent=True)

    # ---- per-service record creators -----------------------------------

    def _create_mysql_records(self):
        admin_uid = self._add_user("MySQL Admin User", "root", self.creds.mysql_root_password)
        rotation_uid = self._add_user("MySQL Rotation User", "sqluser", self.creds.mysql_user_password)
        db_uid = self._add_resource(
            "pamDatabase", "MySQL Database", host="db-mysql-1", port="3306",
            connection={"protocol": "mysql", "database": "salesdb", "userRecords": [admin_uid]},
            port_forward={"reusePort": True})
        self._enable_connection(db_uid, admin_uid)
        self._allow_resource(db_uid)
        self._tdag.link_user_to_resource(admin_uid, db_uid, True, True)
        self._tdag.link_user_to_resource(rotation_uid, db_uid, False, True)
        self._rotate(rotation_uid, admin_uid, db_uid)

    def _create_ssh_password_records(self):
        admin_uid = self._add_user("SSH Admin with Password", "linuxuser", self.creds.ssh_password)
        machine_uid = self._add_resource(
            "pamMachine", "SSH Machine with Password Access",
            host="server-ssh-with-pwd-1", port="2222",
            connection={"protocol": "ssh", "userRecords": [admin_uid]},
            port_forward={"reusePort": True})
        self._enable_connection(machine_uid, admin_uid)
        self._allow_resource(machine_uid)
        self._tdag.link_user_to_resource(admin_uid, machine_uid, True, True)
        self._rotate(admin_uid, admin_uid, machine_uid)

    def _create_ssh_key_records(self):
        admin_uid = self._add_user("SSH Admin with Private Key", "linuxuser",
                                   private_key=self.creds.ssh_private_key)
        machine_uid = self._add_resource(
            "pamMachine", "SSH Machine with Private Key Access",
            host="server-ssh-with-key-1", port="2222",
            connection={"protocol": "ssh", "userRecords": [admin_uid]},
            port_forward={"reusePort": True})
        self._enable_connection(machine_uid, admin_uid)
        self._allow_resource(machine_uid)
        self._tdag.link_user_to_resource(admin_uid, machine_uid, True, True)
        self._rotate(admin_uid, admin_uid, machine_uid)

    def _create_vnc_records(self):
        admin_uid = self._add_user("VNC Admin", "vncuser", self.creds.vnc_password)
        machine_uid = self._add_resource(
            "pamMachine", "VNC Machine", host="server-vnc", port="5901",
            connection={"protocol": "vnc", "userRecords": [admin_uid]},
            port_forward={"reusePort": True})
        self._enable_connection(machine_uid, admin_uid)
        self._allow_resource(machine_uid)
        self._tdag.link_user_to_resource(admin_uid, machine_uid, True, True)

    def _create_rdp_records(self):
        user_uid = self._add_user("RDP User", "linuxuser", self.creds.rdp_user_password)
        admin_uid = self._add_user("RDP Admin", "root", self.creds.rdp_root_password)
        machine_uid = self._add_resource(
            "pamMachine", "RDP Machine", host="server-rdp", port="3389",
            connection={"protocol": "rdp", "security": "any", "ignoreCert": True,
                        "resizeMethod": "display-update", "userRecords": [admin_uid]},
            port_forward={"reusePort": True})
        self._enable_connection(machine_uid, admin_uid)
        self._allow_resource(machine_uid)
        self._tdag.link_user_to_resource(admin_uid, machine_uid, True, True)
        self._tdag.link_user_to_resource(user_uid, machine_uid, False, True)

    def _create_rbi_record(self):
        rbi_uid = self._add_resource(
            "pamRemoteBrowser", "Bing Remote Browser", rbi_url="https://bing.com",
            connection={"protocol": "http", "allowUrlManipulation": True, "userRecords": []})
        self._tdag.link_resource_to_config(rbi_uid)
        self._pte.execute(self.params, record=rbi_uid, config=self.pam_config_uid,
                          enable_rotation=False, enable_connections=True, enable_tunneling=False,
                          enable_typescripts_recording=False, enable_connections_recording=True, silent=True)
        self._allow_resource(rbi_uid, rotation=False, connections=True, tunneling=False,
                             session_recording=True, typescript_recording=False, remote_browser_isolation=True)

    def _create_postgresql_records(self):
        admin_uid = self._add_user("PostgreSQL Admin User", "postgres", self.creds.postgres_password)
        db_uid = self._add_resource(
            "pamDatabase", "PostgreSQL Database", host="db-postgres-1", port="5432",
            database_type="postgresql",
            # database name must match compose POSTGRES_DB ("postgres"), not the type
            connection={"protocol": "postgresql", "database": "postgres", "userRecords": [admin_uid]},
            port_forward={"reusePort": True})
        self._enable_connection(db_uid, admin_uid)
        self._allow_resource(db_uid)
        self._tdag.link_user_to_resource(admin_uid, db_uid, True, True)
        self._rotate(admin_uid, admin_uid, db_uid)

    def _create_mariadb_records(self):
        admin_uid = self._add_user("MariaDB Admin User", "root", self.creds.mariadb_root_password)
        rotation_uid = self._add_user("MariaDB Rotation User", "max", self.creds.mariadb_user_password)
        db_uid = self._add_resource(
            "pamDatabase", "MariaDB Database", host="db-mariadb-1", port="3306",
            database_type="mariadb",
            connection={"protocol": "mysql", "database": "mydb", "userRecords": [admin_uid]},
            port_forward={"reusePort": True})
        self._enable_connection(db_uid, admin_uid)
        self._allow_resource(db_uid)
        self._tdag.link_user_to_resource(admin_uid, db_uid, True, True)
        self._tdag.link_user_to_resource(rotation_uid, db_uid, False, True)
        self._rotate(rotation_uid, admin_uid, db_uid)

    def _create_mssql_records(self):
        admin_uid = self._add_user("Microsoft SQL Server Admin User", "sa", self.creds.mssql_sa_password)
        db_uid = self._add_resource(
            "pamDatabase", "Microsoft SQL Server Database", host="db-mssql", port="1433",
            database_type="mssql",
            connection={"protocol": "sql-server", "database": "master", "userRecords": [admin_uid]},
            port_forward={"reusePort": True})
        self._enable_connection(db_uid, admin_uid)
        self._allow_resource(db_uid)
        self._tdag.link_user_to_resource(admin_uid, db_uid, True, True)
        self._rotate(admin_uid, admin_uid, db_uid)

    def _create_mongodb_records(self):
        admin_uid = self._add_user("MongoDB Admin User", "root", self.creds.mongo_root_password)
        rotation_uid = self._add_user("MongoDB Rotation User", "user1", self.creds.mongo_user_password)
        db_uid = self._add_resource(
            "pamDatabase", "MongoDB Database", host="db-mongo", port="27017",
            database_type="mongodb",
            connection={"protocol": "mongodb", "database": "mydatabase", "userRecords": [admin_uid]},
            port_forward={"reusePort": True})
        self._enable_connection(db_uid, admin_uid)
        self._allow_resource(db_uid)
        self._tdag.link_user_to_resource(admin_uid, db_uid, True, True)
        self._tdag.link_user_to_resource(rotation_uid, db_uid, False, True)
        self._rotate(rotation_uid, admin_uid, db_uid)

    def _create_telnet_records(self):
        # Compose telnet (nyancat) has no auth; these creds exist only for
        # rotation/discovery testing on the KC side.
        admin_uid = self._add_user("Telnet Admin", "user", self.creds.telnet_password)
        machine_uid = self._add_resource(
            "pamMachine", "Telnet Machine", host="server-telnet", port="23",
            connection={"protocol": "telnet", "userRecords": [admin_uid]},
            port_forward={"reusePort": True})
        self._enable_connection(machine_uid, admin_uid)
        self._allow_resource(machine_uid)
        self._tdag.link_user_to_resource(admin_uid, machine_uid, True, True)
        self._rotate(admin_uid, admin_uid, machine_uid)

    def _create_openldap_records(self):
        # server-openldap-1 uses the rroemhild/test-openldap image with fixed
        # demo credentials (documented, not generated).  No compose secrets.
        c = self.creds
        admin_uid = self._add_user(
            "OpenLDAP Admin", c.OPENLDAP_ADMIN_DN, c.OPENLDAP_ADMIN_PASSWORD,
            notes=f"OpenLDAP directory admin (image-fixed). Domain: {c.OPENLDAP_DOMAIN}",
            distinguished_name=c.OPENLDAP_ADMIN_DN,  # bind DN for directory rotation
            quiet_policy=True)  # image-fixed creds intentionally don't meet policy
        dir_uid = self._add_resource(
            "pamDirectory", "OpenLDAP Directory", host="server-openldap-1", port="10389",
            directory_type="openldap", domain_name=c.OPENLDAP_DOMAIN,
            connection={"userRecords": [admin_uid]}, port_forward={"reusePort": True},
            notes="OpenLDAP demo directory (rroemhild/test-openldap, image-fixed users).")
        # Directories have no interactive connect protocol; enable tunneling for
        # discovery/rotation reachability. The admin is image-fixed (not rotated).
        self._tdag.link_resource_to_config(dir_uid)
        self._pte.execute(self.params, record=dir_uid, config=self.pam_config_uid,
                          admin=admin_uid, enable_connections=False, enable_tunneling=True, silent=True)
        self._allow_resource(dir_uid, rotation=True, connections=False, tunneling=True,
                             session_recording=False, typescript_recording=False,
                             remote_browser_isolation=False)
        self._tdag.link_user_to_resource(admin_uid, dir_uid, True, True)

        # Demo users. Their initial password comes from the image; the gateway
        # rotates them via the cn=admin credential (rootDN has write access to the
        # planetexpress DIT). Rotation must be CONFIGURED here - just linking a user
        # to a rotation-allowed resource makes WV show a rotate button that would
        # otherwise fail with RRS_NO_ROTATION (no rotation settings). Same pattern
        # as the DB rotation users (sqluser, max, ...).
        for login, password, dn in c.OPENLDAP_DEMO_USERS:
            user_uid = self._add_user(f"OpenLDAP User ({login})", login, password,
                                      notes="OpenLDAP demo user. Initial password from image; "
                                            "rotated via cn=admin.",
                                      distinguished_name=dn,  # kdnrm needs the DN to rotate the entry
                                      quiet_policy=True)  # weak initial creds; policy noise expected
            self._tdag.link_user_to_resource(user_uid, dir_uid, False, True)
            self._rotate(user_uid, admin_uid, dir_uid)

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


def build_compose(network_id: str, gateway_config_b64: str, creds: PlaygroundCredentials,
                  project_name: str = "") -> str:
    """Render the full docker-compose.yaml (name + network + gateway + 11 backends)."""
    parts: List[str] = []
    parts.append(
        "# Generated by Keeper Commander `pam project import --sample-data`.\n"
        "# Credentials below are also stored as records in your Keeper vault.\n"
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
    ], network_id))

    parts.append(_backend_block("db-postgres-1", "postgres", [
        ("POSTGRES_DB", "postgres"),
        ("POSTGRES_USER", "postgres"),
        ("POSTGRES_PASSWORD", creds.postgres_password),
    ], network_id))

    parts.append(_backend_block("db-mariadb-1", "mariadb:10.8", [
        ("MARIADB_ROOT_HOST", "%"),
        ("MARIADB_ROOT_PASSWORD", creds.mariadb_root_password),
        ("MARIADB_DATABASE", "mydb"),
        ("MARIADB_USER", "max"),
        ("MARIADB_PASSWORD", creds.mariadb_user_password),
    ], network_id, extra=[
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
