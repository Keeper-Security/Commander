#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander
# Copyright 2022 Keeper Security Inc.
# Contact: ops@keepersecurity.com
#

import requests
import os
import json
import logging
import ssl
import time
import sys

from typing import Union, Dict, Optional

from .params import RestApiContext
from .error import KeeperApiError, Error
from .proto import APIRequest_pb2 as proto
from . import crypto, utils
from cryptography.hazmat.primitives.asymmetric import rsa, ec

CLIENT_VERSION = 'c17.2.0'

SERVER_PUBLIC_KEYS = {
    1: crypto.load_rsa_public_key(utils.base64_url_decode(
        'MIIBCgKCAQEA9Z_CZzxiNUz8-npqI4V10-zW3AL7-M4UQDdd_17759Xzm0MOEfH' +
        'OOsOgZxxNK1DEsbyCTCE05fd3Hz1mn1uGjXvm5HnN2mL_3TOVxyLU6VwH9EDInn' +
        'j4DNMFifs69il3KlviT3llRgPCcjF4xrF8d4SR0_N3eqS1f9CBJPNEKEH-am5Xb' +
        '_FqAlOUoXkILF0UYxA_jNLoWBSq-1W58e4xDI0p0GuP0lN8f97HBtfB7ijbtF-V' +
        'xIXtxRy-4jA49zK-CQrGmWqIm5DzZcBvUtVGZ3UXd6LeMXMJOifvuCneGC2T2uB' +
        '6G2g5yD54-onmKIETyNX0LtpR1MsZmKLgru5ugwIDAQAB')),

    2: crypto.load_rsa_public_key(utils.base64_url_decode(
        'MIIBCgKCAQEAkOpym7xC3sSysw5DAidLoVF7JUgnvXejbieDWmEiD-DQOKxzfQq' +
        'YHoFfeeix__bx3wMW3I8cAc8zwZ1JO8hyB2ON732JE2Zp301GAUMnAK_rBhQWmY' +
        'KP_-uXSKeTJPiuaW9PVG0oRJ4MEdS-t1vIA4eDPhI1EexHaY3P2wHKoV8twcGvd' +
        'WUZB5gxEpMbx5CuvEXptnXEJlxKou3TZu9uwJIo0pgqVLUgRpW1RSRipgutpUsl' +
        'BnQ72Bdbsry0KKVTlcPsudAnnWUtsMJNgmyQbESPm-aVv-GzdVUFvWKpKkAxDpN' +
        'ArPMf0xt8VL2frw2LDe5_n9IMFogUiSYt156_mQIDAQAB')),

    3: crypto.load_rsa_public_key(utils.base64_url_decode(
        'MIIBCgKCAQEAyvxCWbLvtMRmq57oFg3mY4DWfkb1dir7b29E8UcwcKDcCsGTqoI' +
        'hubU2pO46TVUXmFgC4E-Zlxt-9F-YA-MY7i_5GrDvySwAy4nbDhRL6Z0kz-rqUi' +
        'rgm9WWsP9v-X_BwzARqq83HNBuzAjf3UHgYDsKmCCarVAzRplZdT3Q5rnNiYPYS' +
        'HzwfUhKEAyXk71UdtleD-bsMAmwnuYHLhDHiT279An_Ta93c9MTqa_Tq2Eirl_N' +
        'Xn1RdtbNohmMXldAH-C8uIh3Sz8erS4hZFSdUG1WlDsKpyRouNPQ3diorbO88wE' +
        'AgpHjXkOLj63d1fYJBFG0yfu73U80aEZehQkSawIDAQAB')),

    4: crypto.load_rsa_public_key(utils.base64_url_decode(
        'MIIBCgKCAQEA0TVoXLpgluaqw3P011zFPSIzWhUMBqXT-Ocjy8NKjJbdrbs53eR' +
        'FKk1waeB3hNn5JEKNVSNbUIe-MjacB9P34iCfKtdnrdDB8JXx0nIbIPzLtcJC4H' +
        'CYASpjX_TVXrU9BgeCE3NUtnIxjHDy8PCbJyAS_Pv299Q_wpLWnkkjq70ZJ2_fX' +
        '-ObbQaZHwsWKbRZ_5sD6rLfxNACTGI_jo9-vVug6AdNq96J7nUdYV1cG-INQwJJ' +
        'KMcAbKQcLrml8CMPc2mmf0KQ5MbS_KSbLXHUF-81AsZVHfQRSuigOStQKxgSGL5' +
        'osY4NrEcODbEXtkuDrKNMsZYhijKiUHBj9vvgKwIDAQAB')),

    5: crypto.load_rsa_public_key(utils.base64_url_decode(
        'MIIBCgKCAQEAueOWC26w-HlOLW7s88WeWkXpjxK4mkjqngIzwbjnsU9145R51Hv' +
        'sILvjXJNdAuueVDHj3OOtQjfUM6eMMLr-3kaPv68y4FNusvB49uKc5ETI0HtHmH' +
        'FSn9qAZvC7dQHSpYqC2TeCus-xKeUciQ5AmSfwpNtwzM6Oh2TO45zAqSA-QBSk_' +
        'uv9TJu0e1W1AlNmizQtHX6je-mvqZCVHkzGFSQWQ8DBL9dHjviI2mmWfL_egAVV' +
        'hBgTFXRHg5OmJbbPoHj217Yh-kHYA8IWEAHylboH6CVBdrNL4Na0fracQVTm-nO' +
        'WdM95dKk3fH-KJYk_SmwB47ndWACLLi5epLl9vwIDAQAB')),

    6: crypto.load_rsa_public_key(utils.base64_url_decode(
        'MIIBCgKCAQEA2PJRM7-4R97rHwY_zCkFA8B3llawb6gF7oAZCpxprl6KB5z2cqL' +
        'AvUfEOBtnr7RIturX04p3ThnwaFnAR7ADVZWBGOYuAyaLzGHDI5mvs8D-NewG9v' +
        'w8qRkTT7Mb8fuOHC6-_lTp9AF2OA2H4QYiT1vt43KbuD0Y2CCVrOTKzDMXG8msl' +
        '_JvAKt4axY9RGUtBbv0NmpkBCjLZri5AaTMgjLdu8XBXCqoLx7qZL-Bwiv4njw-' +
        'ZAI4jIszJTdGzMtoQ0zL7LBj_TDUBI4Qhf2bZTZlUSL3xeDWOKmd8Frksw3oKyJ' +
        '17oCQK-EGau6EaJRGyasBXl8uOEWmYYgqOWirNwIDAQAB')),

    7: crypto.load_ec_public_key(utils.base64_url_decode(
        'BK9w6TZFxE6nFNbMfIpULCup2a8xc6w2tUTABjxny7yFmxW0dAEojwC6j6zb5nTlmb1dAx8nwo3qF7RPYGmloRM')),

    8: crypto.load_ec_public_key(utils.base64_url_decode(
        'BKnhy0obglZJK-igwthNLdknoSXRrGB-mvFRzyb_L-DKKefWjYdFD2888qN1ROczz4n3keYSfKz9Koj90Z6w_tQ')),

    9: crypto.load_ec_public_key(utils.base64_url_decode(
        'BAsPQdCpLIGXdWNLdAwx-3J5lNqUtKbaOMV56hUj8VzxE2USLHuHHuKDeno0ymJt-acxWV1xPlBfNUShhRTR77g')),

    10: crypto.load_ec_public_key(utils.base64_url_decode(
        'BNYIh_Sv03nRZUUJveE8d2mxKLIDXv654UbshaItHrCJhd6cT7pdZ_XwbdyxAOCWMkBb9AZ4t1XRCsM8-wkEBRg')),

    11: crypto.load_ec_public_key(utils.base64_url_decode(
        'BA6uNfeYSvqagwu4TOY6wFK4JyU5C200vJna0lH4PJ-SzGVXej8l9dElyQ58_ljfPs5Rq6zVVXpdDe8A7Y3WRhk')),

    12: crypto.load_ec_public_key(utils.base64_url_decode(
        'BMjTIlXfohI8TDymsHxo0DqYysCy7yZGJ80WhgOBR4QUd6LBDA6-_318a-jCGW96zxXKMm8clDTKpE8w75KG-FY')),

    13: crypto.load_ec_public_key(utils.base64_url_decode(
        'BJBDU1P1H21IwIdT2brKkPqbQR0Zl0TIHf7Bz_OO9jaNgIwydMkxt4GpBmkYoprZ_DHUGOrno2faB7pmTR7HhuI')),

    14: crypto.load_ec_public_key(utils.base64_url_decode(
        'BJFF8j-dH7pDEw_U347w2CBM6xYM8Dk5fPPAktjib-opOqzvvbsER-WDHM4ONCSBf9O_obAHzCyygxmtpktDuiE')),

    15: crypto.load_ec_public_key(utils.base64_url_decode(
        'BDKyWBvLbyZ-jMueORl3JwJnnEpCiZdN7yUvT0vOyjwpPBCDf6zfL4RWzvSkhAAFnwOni_1tQSl8dfXHbXqXsQ8')),

    16: crypto.load_ec_public_key(utils.base64_url_decode(
        'BDXyZZnrl0tc2jdC5I61JjwkjK2kr7uet9tZjt8StTiJTAQQmnVOYBgbtP08PWDbecxnHghx3kJ8QXq1XE68y8c')),

    17: crypto.load_ec_public_key(utils.base64_url_decode(
        'BFX68cb97m9_sweGdOVavFM3j5ot6gveg6xT4BtGahfGhKib-zdZyO9pwvv1cBda9ahkSzo1BQ4NVXp9qRyqVGU')),   
    
    # ML-KEM-1024 keys (base64-encoded PEM format)
    # QA (key ID 107)
    107: crypto.load_mlkem_public_key(b'LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUlJR01qQUxCZ2xnaGtnQlpRTUVCQU1EZ2dZaEFLN0VwZURueVNIM3p0QmNhZXFBWUJxaWJaNGpQSHNvWXVaYwpKVG9sV1o4QnE1LzZwMDNJZVgxMnljS1FHNTc2Q0d1bFV0TkRIalVvUWJ3Nk9telNFZGtVYnF1SlpJQjFGelgyCnFlL1pmQ1E0dXNaWlgxU3lrWithYkZheHFsNU1tOFl5Ui9WRFVGaVNxK1U3cTEwWnh2VnBaZE1Wd2d1cWFSemIKTTJkM3V3LzhiZVpCVHRqVXVUMVpmTjdqYWZrS2U0a1FNM0JMWXM3d2VlYVpLd0c4aHBBQUM1UXFyRGtqRDFseQpPZU9McGJmQkZRb0ZOUWtaUEx6TERVcGpSdkpqdHhYQW9OSzVnTzVZelhVa0QwSTBOdDlUU2FnM2tYWlZBR1hKClN2SUpMTjFpaGRBaUxHMVptMDJTQWhYckhlTmdzUFFteDdyR1ZJeXFNbFNBejFhTUJaaDRPOXBISmo2THdjREwKbnJCb04zS0FJL3phQlFKVXNvbDdMNER6VEEzSWpRL21lem9rYVN2bmh1a1JzbEw0WEhaY09wT1JjNDN6V20rVwpZc2ZZUjVLR1laTWh2b2ZYc2MwOGNZSFhydWdEQ3hDcGRrQjdWNmFwWHVNM3BUa29qclpJQXZBVWNqMzR3K1R3CmNLeWJIYnNLRjM5Q3BZdzF6OUhIZ0pqMnpHa2pHbTNqSTl3aVdQRHJoMlRpTWMwQmRpZk1SSndBdmNMamc5aEoKVFhGY2prT3BjaFFybmwzNkh4M0h2NERBQ0dhUUFXVldROGJBZG95d1Z0VlJkY3BMRVc5VEFJejJBUnhWZTJDWQpSOG9qQ04rRlVXejZOYU41YXZiNVB1SzhEOEdGRmcxa0hqdzFKSW1Mc1VFN04rbHNGMVFMV1BsemhmUnpKNUVZCnl0dWJLbGY3c00yd0NCd01uL0VxSmxSMUYrd0xZOGpHTHVkbmQ5NUpCNFlnTzZINmw0OEFTdXZhSFVmQXBNMnAKdm5vQ3BMbEZwWkR5WGcxOGtmd0lhV0lRS204Nm9FQjhPMElhUkdzZ1NFdmNVWEFvc1RqU3hwQ3JaL01TTFB1aAp5b1R3bzB4QXhEZnlJMWNUUGh4R1A2eDZXUDhFbG9tN1RUeER3SUFCTFdVa0NGc295Y2p6RVdFeElDV1JBVkZKCk5ZWXJqWXZ4UllqVE85Y0pDWlhjWjRJcVhWbUhmU2hiZWJJUk1UdUFnTThiWGR6RGs2eDBCQWJsemMraGkrZEgKWWdTYm9xRVVlVUlZQW5YVFhvd0hIcmZGSmRIYmdGN2dzaU5rQTJad2tIOUVUdmUyZldwY0dKWld3T3V4R1RFbgpBYXVyUE5aUUtxbDFqeVRUVmtHMEJGYzRuWm5WdHZHU0cyam1qeXpsTGlLbUNiL3lldEY3aXkzR0QrSWF6QVFECmFyY0FHL3h6WlZ4bWx0T3J5VSs4R3JCRE00UXlsVFVxUmJPRldFakpOYlNFZXNJN0tSbUNVUmhoTzRhWW1nd2oKeWprRVh0dUdOaHp5UkFaalJscGpJMFJDcVdXQ29OcDdGZloxcncxVW9TcUpkU2FXVE5wQ1BRQkVEeUNLUFdZaAp3WlhvZnpwOHAxbkFsUUhaZldiRHBLVHJUQlQyV3FmSUtLS3FqTGRoVHZvS0gwcVJwQlpEYk9OV3VZTVJucWtSCkU0Z2JLR3ZtVGNxcXRzQ1p1KzZpYWtyd3VlS0Jqb3hSUDVueVFSOUNPQldvY3VpcEp2c3lxeVJBTG5vV2xVMTEKUjJwb0NYa3BIeTNwcmQxbFpZRDhHWXpTVEllUmJEUEZ2SzNKUk8vTWlObG1LV1BZdEVZVGlaRFZZZ1JuSitSSwpMNEJFU1R4TEN6dTBnYjRpY0hyWmxFTWxGV3pnTWwrR29QM0FTZG41bEpNRlVMb1ZlajNiSjA2aFgxZG5UTnFiClcwSUhLS2NxYng4b0lJZGJ4YUtER0F5RkFtZTZud1dXTWUyWEpWZE1LSG5DUm80aXZaaW9FNWJwcHg3Wk1kY3cKaEU3VGJtMEdnd0RaS1FKV1pDcmt1TmxuTTFBeE02Y252RHFYbUlHaGVqU0tKYWpSYlA2WllHVllZUGYyUVJDRwpYSnpSbmRiSUc0TjRyZjBaT3hHVnlReHdmK25GcUV2RlZ0Vm5LdTloUWFSUXpsZzRvZ21xY05FSkp3dmFYd2Y0CkZlODV1cHlhY3hVWENKeUtocmpUU1hUSEFtNWp3RmRIQ2djUmtlejN5a3VDZ2k2RXdobkxVdDN5cVJQa1BtU1EKVGNGa2NBZm5LSUhyTG4wSGE5YUNpZDhWeWJjeG5LREN0cC9Ua2dBRXJiZHdQMWZtTDVGVmMyOUdkOWh6QnUvVApZQUFIZ2h2Y1Y1SW5WU3lLY3k3b1lPQUVFVmM2VjMvSUs4dXFnV1ZLYVd6d3E0a2tnYS9ydzVTU0I0ZW9MdS9zCnRYQzR0c3g0cDY0anFCSlRDdDMxaU5TVHV4MUNMY1N3aDY1TXliZUVkamZaemcvSUE2aUN0ZXZqaHZVckxFRFoKWHNlWHRERlpHd0FOQVVkWnArekVrd2IzcjhObFhMRXlhQ01WeENJMHZPMzBiN21uY0t5cXNONXloVGowZ21jNApBdTF4YmM4U0tXczBnaGxvditVVWcxcDBseGl5YnpYQ29YTDRINllKT0kwcUJIUXlDZDlCVkF4Y3g1THJGSjMxClFHMDV3aUZnbUF5bHNwT3h2RzdFWEZXY0RjY0NpZXh0ak0rR3Q4cTVHTHNXaFpoaVYrUkhRaERPQkZuSGhlYTEKVnQyVUxyODYKLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0tCg=='),

    # Staging (key ID 124)
    124: crypto.load_mlkem_public_key(b'LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUlJR01qQUxCZ2xnaGtnQlpRTUVCQU1EZ2dZaEFLRGxrU0FJWDVyaFZkRm9oOTBNWnpkVHZOVmFwVkhUemx5YQpzU0Y2U2hTaGNXYUNYeXJoa2owV1E4MjRSV0xzRUhIRGJNTWlaYnpHZEF1UnJqMzhLQmxzajdkaFRqaW5LRFBLCndFZzZhOVpZcnVaMFpvZ1N4U2s4VEJ1cW5IQ0V3K0YyY3NlcEcvQ21XVFo4cnRYcmtrQmhPM1ZaZmd5RE5ja28KdVRDalVTWUZxOXhxVzRTUU5LQ2NaN2NhZjFscFhRSjZoS3RyYnBGcUNvbkl0K0dCQ0laMEhsNXdiWHBGUURORgpPNCt4Y3h4R3VRV2luV3lLVCsrRlFFdTBuTEVqSEVhSmFFRmtySU9YaURqM0FFKzJYTW5GSWJXNG91Nkp1alVCCkVoQ2NZVkhZekZrMHhZbEJoS0VRWUxTV0dPZmNKTWRDTDBHNmxFL0trcE5DSk4zMnJINHlFVUhvVm5pcE91OUMKbnhRYk1CMGFvS3phbU4rOEFsRHpyZzB5bytKcHpxdVlKRUVvcnVlUnIyTTZWRmVKdUdDVE1VVDRLZmtjejJNSgpHN3lyV1NDb0RMQ3pua2RHaGdrd0tYVkFKOXhhTVVEY1lDMUtrRnZtakRjbExSeUxNUFdjRjhaMEFKaEpJbitWCkRZaGd3MzRFbkpwSVNoeXJRdE5CYlVjRFJVWm1tYmkxTUtxNWN1QXlwODM4Q1RpWXp3QXdnMHFhSHBjTVVDT3kKUk5jakdmZjFGc2NFZ0pPUUlCUURWd243bTY3SmV5ZTRvUldzc01mbElWaGxGOXVNUWNseHdMQmx2NFR3RVRqMQpmcS9aUVdKTFdoWkFYMlpxSTRvMFFqdW5kS0JGYzZIeWFaRURJMlpsUk04bWFJaGNOWmlURjZhYUVsbFFmNVJDCnZ5NllyRm1sSms5U2M3YUFEWlMyWEcrWHdaTGFZb1REUU96UndmNHFDblExaGpjV3RKb3JyV2FvVmd6enJQTzQKRHIvRGJ1OUVYUmNhRkJwd2pJQUVNS3h4SzNtMVhXU2doanNYZkgyRHF4bnFCOUpGZ3ZaZ08vdkJpa0tuYkpqbApMVlhNa0U2QXE3RDVGd2I0eW9iNnNIeklxN0k1TzlMb21la0FBWFFjdTQvYkx3c29zbzJsUnlXSWtuMFNRNmpRCmVPejhsYkpJUjkxckp6Nm9YeW5FSzZFeU9xVTV3bUhTWGlSNEtpZ3FkaUFubG1XQ20wVzNpa0RpUC93NW1LZGcKdFFBZFR3ZTV4UTlRRmJyNXhwem5pMmtXaE85b2RYVGNsVUNCY3N5RHNQRm1OdVBnZjROU1YxSnNtb2tGT003NgpLQmlaUXE1cHVwL3pEZCtydEVkbk1Gc0tmUlkwUEcxakdBcmFtMGw3Y0xha0t6TkR5Q2g4YlhsS3FrdXBGcG81CnN1LzRUMU1HRzJJaExNeGltQ04zeFEraHk3cllwdkR5RW9lc2c1WDVjTTRXbVR1Q28zc0dITkUzU3FiSHJaangKZlFMQVU1UVhJajhwVHV1cFBZaEp3c0NBWUIwcXJRNjJsRkRWVVd6V2xNLzFVb3NWZjdoQ1BHYjZBYzRSTVZzTAp4OVljUXRNa1hTckpHZlJuWWxNNVh2b2dFZUdBVU5LSWx6L0xneFFveGU2b1AvNUJ3RGo3VmdZeW96ZDdWOEFwCnNDWjdjTVZFY1d6UUJhbWhrbktpVXNCcEVKUmh6bHZ4UzVVWkdUb0RmODdhUThpc2VFNjZ1RW9EbmZpaFlnSG4KdEJvS1J2VUtLdFAzeDJDWXVsN0NuUzRsekhlV1UxQUZxSkFwT0ZhR1hpV0RXTytXZUc1R1JSSUp3bk9Ub3hieQpaaXNEYzFyN3VmM25lVUtJaThYZ0ZuYWJNcUJreXNhN2lVZlZSd3FqRnBHWW5rNTdmclVCalY2bk10bWFuTnB3CmMvSnJwTllJelplcmRuR1RyNXdBbWx1SnpjWVdKVXloemVQY3d5ejJKbGMwRk8yQUJIUzFQclNNYi95QmpodmIKcFNvVVhhR0FxellEaUowRmFlOHlWRWxTRlE2Q3ZZNXNjYTdyVE1zcGRNVzNyQWZKV0hnRHUzK1F3cmpoZVVwSwp1Q2d4ekdOaGdLTnN5eUJ5WXVKVWU1azRxeW9BcGNnVkZBUzJTUUVFbmdLNHA1OGtSc3RtUFdnYm5CMjNhcjU2CnFvd1lCVjV4UTJTMnJIZzd0R3pBQnJGVFM2aHpGSDJncXVaNFIxQXlIdnFRV2pMaHBxdmFUR3pLZFpEVUkvRVgKaVZSS2dTd0l0bVhFZFVIaXZNN3NzUGZDUmVIQ3dMMlNmZHp6V1puVHZPMUpxUVZDUys5a2w1aWxDWmMyYlJkcApabXRVR284R0FqazVja0hEVDkzSkhkeW9yZEZZbndqMWNTV3FvOFFneTU0WW1rQWdDeXhXWndPMUxoL0JSRm5pCldYYWNzV0JEcXN6c0FOVUt1eVkyR0hWaWZxRkVud3hwZW5ZRHhhU0pGYmRvZCt4UlE4K0lUZ3N6UGtpSUtwUksKcUFPcXhnd2dGcTcwcjRyM3JKUUZWRWRvZzRwU3NwYVNvbFB5dG85b1NoWjJld2RFTC9xeGZybEJCeHZtV002RApwcENKZ0szWG1yOVl1MVBrdUEyVXJoRFNaenVEWXNDcGNzWEFINjNIZnhtQ0JxSlZtdWFRenlITFZjSTZtMUxZClJzYzdwSWhwTHUrckxuNnJ0bjBYVDJyaXk3akhVNTMrcjF6ZEUwYVBrVDIzL0JxNG8wb3ZWRGZ1ZGpsT3hPd3UKNmxDU3hNWlkKLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0tCg=='),

    # Prod (key ID 136)
    136: crypto.load_mlkem_public_key(b'LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUlJR01qQUxCZ2xnaGtnQlpRTUVCQU1EZ2dZaEFCZlJTaTlXaEttekRMR2toL2lJTnhEbXRheVZIUzliendGeApOOEhCVXFXOFBNbElDTnpWbTBuRFAwdDRhTnhFRmNYYmtvMHdWbjZYRzdGYlpNZW5PVUdybEdGY2Q2N2NlVzRJCkRLL2xmeWtrd3VVWUdLWkNHY0Iwa3FNYUR2ajFXcGpscVp4aW16UUxGYkprRm5QRm92Q1RFQnd4Wis3c09hVlQKR1ZoS3VialNVU3dDcjZwVmFPRk1kWFUwaUdrSUxBWHl6YjJHVHZhaGFYTzF3cFdsUGpZWHgzbkRadDRSQjBJSgpwWXNjYk5CMnprS3BvdmRHS3dtY0V0NXBJeFlMd0RXcms1b1V4WXJsbTRLRkc5eEZvV3JyR3M1VU53T2JabzhrClVadkNFcDRsYXdwanEyeE12dmRxbnRzMnJCTXN5K0pxWFZsRFk4d2tBdXFxeW5PQ244aDJpWWNIV3FxSEdLZFYKWnNCSmtxNW5iK2J5cVI2RWhuQUdSQWpEaFVGUkRicmhGNVhMQnU1R0JEcHhKOUpaWlpZRGsyMmNEYkt5S1ZZeAp3Q2hpU0dqZ284VHJIT09uUWRWNk14MExtYlAwSTJVYVNoRDdDU1kzRGQyRmNJSldnN2l3ZDE0SFlyUkNTZGFKCksxbUlBdUhvUjZwQ21Ha2txRS93VTRlbnZJNm5yR0tSZVVqb3hqTFFFdEtZbVJ2OHhsOFlHTGdtbVZGS2JXaW8KdGhYY243WDRBaVJMU3hmWnhhelNQeGpxTEEzTW5RUVZ0bWRMRVg5V2xBNHlONXlTcnpEYUpDRTBPKzUwUjQvTQpvNkhoSVF3R2Vuclp2bzB3d2tUaHlIajZLSTREc0tVWWt5VWNYZ0Vjdlp2WXRnVmhtYnFLdmQzbGNjN2pML1oyCnhVK1RaS2NjS05XSnl0S2dJYWVnSzVDMG9WeURNdTNaQzBFVkZiVmFpb0Q1ZHBjbGNLb2xrbXN6UDdkaXBnTW0KUFMyQ2ZjUWlNVlRTVkFyemEyY3hDNnlMQ1hVVWF2UW5kQ2dZYmhKc1ZNQmd3OU5hamMxVG5KWU1KOGtBekpregpSN1owdU9vbkY5UUpROEpLdDFkMnRjUTRSZGVFak1GV1N4NUlzWThxTUZSaWhhQkxNSGVsTWRoZ0d1VGxmdkNUCmcxbFJzWVNJTFZiS1daSldyclh4akpWMFpmYklmRklndXQzY3FLN0R4NmZFS3l1N2dhZG1RSVpKa0F4U0s2ME0KblZJV0pJRkxSQU53UGNZYUhXam12VjhtZWhsVnhSQXdkVU40cll0Z1pLR2dXWEN5SGZERW9JMm9UbE02dUdHRApFOUpzRC9xS3hKSUxvNzlnWVVwckxoWkFycnBwTEVzVkRzNlltdmVwYkg2V3pmdnJyYklpSVpxb0p2YXpQVFFICkkrWmpHd3NITHJtQVcyajRWdkVJd0lXTGY5cmd1ZDNCQ3VBVk1ZTUZEZnNnbnpLaG1jTzFwU0pYcHJsRWVjekEKSkxFOGxqN0t2SHJIWHg1MXYwUGxvZkxJVXppVUVRODVMNk9DbFFZeUNxRHlUenNDcHFQMUw5TklDSXNBZWZZcApwMElSSnV6R01sdWJMblRaQTVjRVk3UDNvYldGVTRJbGNvZ1VTaDk2eWxaaVVGMGdHNUZWYm1uY2pHUzBNdWtwCkZyMjVxWHBGTThJQWhIV0dZN056SU9yMXdZaUJtZW1Kdml1MmJLK3dzMjVnbHEzR1c1WW54YXpoQ0JHb0ZlNFIKbThuaFppS1dmclZjRlJJNEtVenl3RzZzWDI3Y2h6YnJpdGtjVGVUVEM4TzFjY3lTVXprOEwzWFpQVGt6U1pOawpPV3pHU1hmb051ZkdqbFBxcGcyZ1NNbUdqN2g2VXY5NUk0TkxQR1Z4dE1QRERtUmpkdm5tcXZHMWtkMDJ4WGZyCm83STBkckVwR0ZYbUJuRWllbDc3UmUxTFZ5K3dueE5ybzBUSGZKUDVWdXJXdzJlTGdOZXdiOWwxWnFOWEZoRFcKSXN0bGVRbHlaT0ZKdmFrV3JZWmNVYlk3SW56MnJKR01kdWt3dHNoWldEWENmdXdzQ3NGMGI0T0ZGakVtTnA0RAplZDBWQ1lvS0VQTnBZdVk3SDkxN1VNQVNMZWZFTXVzWlU4dzBrOWJISDB6cnNuUHdNSWk0Q2hBamdtTVVrNHBvCnF1S2pyN013U2Fmd0FCeGpSM1Y3SUtNWWs1WkRReStrQ0MvcVNBM0x0KytLSk0rcHVYdUxkdk1NRm9nMWo0VnIKdGNBQlpxZExiQ3ZEUG5mbWVGRldQQlptQjYySUdEWndPNHRZeDFJc0dJbzRScGNsZHlsSWxvYWpzWWhuemVDMgpFWENTb3RMNXBWS01mZSt4ZDhxa2ZRVERHc2lIYmg4NHE3QWt1a3FnbkZ0M1diSkZHNVBZeWl5d2EvUHlIWnJtCnFHUlRScDVsQUVMbkRyQjNHdXFxVE41NmZwRlpDUHc1ZktJUUJuRGpwUTFvVTYvZ2htbDNIZDhTZXQwRUJqQzIKRVJTWXE1RkREOXVxcnVvYW00WkxtVjRqdTlkcFdsK01tM1ZIWnNYWHRocEpnNXk4czRXRGtFa2xJakpndzJJSgpvMjFITnhnbkZhd2tSNXJHeVU4cEt1cDNrQWZ5bzlaVGhaUUdyWHVFUTFQeXhsOGxzYVNKcmtLUndxakdzeWFWCmdxUGhtcmdBZ1VnWVJRN25LTDh5bTE0M25iT21hYXQ1UVN2MC9SR2o3eGdFZytoVHR0NnIvaDhWQk1oNEoxdmwKWkI0VllxNU8KLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0tCg==')
}   # type: Dict[int, Union[rsa.RSAPublicKey, ec.EllipticCurvePublicKey, Dict[str, Union[ec.EllipticCurvePublicKey, bytes]]]]


def encrypt_with_keeper_key(context, data: bytes) -> bytes:
    key_id = context.server_key_id
    if 1 <= key_id <= 6:
        return crypto.encrypt_rsa(data, SERVER_PUBLIC_KEYS[key_id])
    elif 7 <= key_id <= 17:
        return crypto.encrypt_ec(data, SERVER_PUBLIC_KEYS[key_id])
    else:
        raise KeeperApiError('invalid_key_id', f'Key ID \"{key_id}\" is not valid.')


def execute_rest(context, endpoint, payload):
    # type: (RestApiContext, str, proto.ApiRequestPayload) -> Optional[Union[bytes, dict]]
    if not context.transmission_key:
        context.transmission_key = os.urandom(32)

    if not context.server_key_id:
        context.server_key_id = 7

    run_request = True
    while run_request:
        run_request = False

        api_request = proto.ApiRequest()
        qrc_success = False
        
        # Try QRC encryption if qrc_key_id is available
        if context.qrc_key_id and context.qrc_key_id >= 100:
            qrc_mlkem_key = SERVER_PUBLIC_KEYS.get(context.qrc_key_id)
            if qrc_mlkem_key and isinstance(qrc_mlkem_key, bytes):
                try:
                    logging.debug(f"Using QRC hybrid encryption (ML-KEM key ID: {context.qrc_key_id}, EC key ID: {context.server_key_id})")

                    if not context.client_ec_private_key:
                        context.client_ec_private_key = crypto.generate_ec_key()[0]
                    
                    from .qrc.qrc_crypto import encrypt_qrc
                    ec_public_key = SERVER_PUBLIC_KEYS[context.server_key_id]
                    qrc_message = encrypt_qrc(context.transmission_key, context.client_ec_private_key, ec_public_key, qrc_mlkem_key)

                    api_request.qrcMessageKey.clientEcPublicKey = qrc_message['client_ec_public_key']
                    api_request.qrcMessageKey.mlKemEncapsulatedKey = qrc_message['ml_kem_encapsulated_key']
                    api_request.qrcMessageKey.data = qrc_message['data']
                    api_request.qrcMessageKey.msgVersion = qrc_message['msg_version']
                    api_request.qrcMessageKey.ecKeyId = context.server_key_id
                    
                    qrc_success = True
                except Exception as e:
                    logging.warning(f"QRC encryption failed ({e}), falling back to EC encryption")
        
        # Fallback to EC encryption if QRC not available or failed
        if not qrc_success:
            server_public_key = SERVER_PUBLIC_KEYS[context.server_key_id]
            if isinstance(server_public_key, rsa.RSAPublicKey):
                api_request.encryptedTransmissionKey = crypto.encrypt_rsa(context.transmission_key, server_public_key)
            elif isinstance(server_public_key, ec.EllipticCurvePublicKey):
                api_request.encryptedTransmissionKey = crypto.encrypt_ec(context.transmission_key, server_public_key)
            else:
                raise ValueError('Invalid server public key')
        
        api_request.publicKeyId = context.qrc_key_id if qrc_success else context.server_key_id
        api_request.locale = context.locale or 'en_US'

        api_request.encryptedPayload = crypto.encrypt_aes_v2(payload.SerializeToString(), context.transmission_key)

        request_data = api_request.SerializeToString()
        if endpoint.startswith('https://'):
            url = endpoint
        else:
            url = context.server_base + endpoint

        try:
            rs = requests.post(url, data=request_data, headers={'Content-Type': 'application/octet-stream'},
                               proxies=context.proxies, verify=context.certificate_check)
        except requests.exceptions.SSLError as e:
            doc_url = 'https://docs.keeper.io/secrets-manager/commander-cli/using-commander/troubleshooting-commander-cli#ssl-certificate-errors'
            if len(e.args) > 0:
                inner_e = e.args[0]
                if hasattr(inner_e, 'reason'):
                    reason = getattr(inner_e, 'reason')
                    if isinstance(reason, Exception) and hasattr(reason, 'args'):
                        args = getattr(reason, 'args')
                        if isinstance(args, tuple) and len(args) > 0:
                            inner_e = args[0]
                            if isinstance(inner_e, ssl.SSLCertVerificationError):
                                raise Error(f'Certificate validation error. More info:\n{doc_url}')
            raise e

        content_type = rs.headers.get('Content-Type') or ''
        if rs.status_code == 200:
            if content_type == 'application/json':
                return rs.json()

            rs_body = rs.content
            if rs_body:
                rs_body = crypto.decrypt_aes_v2(rs.content, context.transmission_key)
            return rs_body
        elif rs.status_code >= 400:
            if content_type.startswith('application/json'):
                failure = rs.json()
                logging.debug('<<< Response Error: [%s]', failure)
                if rs.status_code == 401:
                    if failure.get('error') == 'key':
                        server_key_id = failure['key_id']
                        if 'qrc_ec_key_id' in failure:
                            qrc_ec_key_id = failure['qrc_ec_key_id']
                            logging.warning(f"QRC key mismatch (server expects ML-KEM key {server_key_id}), falling back to EC-only")
                            context.disable_qrc()  # Disable QRC, fall back to EC
                            context.server_key_id = qrc_ec_key_id
                            run_request = True
                            continue
                        else:
                            if server_key_id != context.server_key_id:
                                context.server_key_id = server_key_id
                                run_request = True
                                continue
                elif rs.status_code == 403:
                    if failure.get('error') == 'throttled' and not context.fail_on_throttle:
                        logging.info('Throttled. sleeping for 10 seconds')
                        time.sleep(10)
                        run_request = True
                        continue
                elif rs.status_code == 400:
                    if context.server_key_id >= 100:
                        logging.warning(f"QRC request failed with 400 error, falling back to EC encryption: {failure.get('message', 'Unknown error')}")
                        context.server_key_id = 7
                        run_request = True
                        continue
                return failure
            else:
                if logging.getLogger().level <= logging.DEBUG:
                    if rs.text:
                        logging.debug('<<< Response Content: [%s]', rs.text)
                    else:
                        logging.debug('<<< HTTP Status: [%s]  Reason: [%s]', rs.status_code, rs.reason)
                raise KeeperApiError(rs.status_code, rs.reason)


def v2_execute(context, rq):
    # type: (RestApiContext, dict) -> Optional[dict]

    api_request_payload = proto.ApiRequestPayload()
    api_request_payload.payload = json.dumps(rq).encode('utf-8')
    rs_data = execute_rest(context, 'vault/execute_v2_command', api_request_payload)
    if rs_data:
        if type(rs_data) is bytes:
            rs = json.loads(rs_data.decode('utf-8'))
            logger = logging.getLogger()
            if logger.level <= logging.DEBUG:
                logger.debug('>>> Request JSON: [%s]', json.dumps(rq, sort_keys=True, indent=4))
                logger.debug('<<< Response JSON: [%s]', json.dumps(rs, sort_keys=True, indent=4))
            return rs

        if type(rs_data) is dict:
            raise KeeperApiError(rs_data['error'], rs_data['message'])
