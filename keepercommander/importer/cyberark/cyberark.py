import re
import requests
from http import HTTPStatus
from os import environ, path
from prompt_toolkit import HTML, print_formatted_text, prompt
from prompt_toolkit.shortcuts import button_dialog, ProgressBar
from prompt_toolkit.styles import Style
from tabulate import tabulate
from time import sleep
from urllib.parse import parse_qsl


from ..importer import BaseImporter, SharedFolder, Record, RecordField


class CyberArkImporter(BaseImporter):
    # Delay between requests to avoid hitting the API rate limits
    DELAY = 0.025
    # CyberArk REST API endpoints (relative to the base URL)
    ENDPOINTS = {
        "accounts": "Accounts",
        "account_password": "Accounts/{account_id}/Password/Retrieve",
        "logon": "Auth/{type}/Logon",
        "safes": "Safes",
    }
    # Request timeout in seconds
    TIMEOUT = 10

    @classmethod
    def get_url(cls, pvwa_host, endpoint):
        return f"https://{pvwa_host}/PasswordVault/API/{cls.ENDPOINTS[endpoint]}"

    @classmethod
    def get_response(cls, url, authorization_token, query_params):
        return requests.get(
            url,
            headers={
                "Authorization": authorization_token,
                "Content-Type": "application/json",
            },
            params=query_params,
            timeout=cls.TIMEOUT,
        )

    def do_import(self, filename, **kwargs):
        pvwa_host = filename.removeprefix("https://")
        query_params = {}
        if "?" in pvwa_host:
            pvwa_host, query_string = pvwa_host.split("?", 1)
            if "=" in query_string:
                # Override the query parameters
                query_params = dict(parse_qsl(query_string))
            else:
                # Treat the entire query string as the search query parameter
                query_params["search"] = query_string
        if pvwa_host.endswith(".cyberark.cloud"):
            # CyberArk Privilege Cloud uses an OAuth2 client_credentials grant for authentication
            pvwa_host = f"{pvwa_host.split('.')[0]}.privilegecloud.cyberark.cloud"
            id_tenant = environ.get("KEEPER_CYBERARK_ID_TENANT") or prompt("CyberArk Identity Tenant ID: ")
            if re.match(r"^[A-Za-z]{3}\d{4}$", id_tenant):
                # Append the ".id" suffix to the tenant ID if it matches the expected format
                id_tenant += ".id"
            client_id = environ.get("KEEPER_CYBERARK_USERNAME") or prompt("CyberArk service user name: ")
            client_secret = environ.get("KEEPER_CYBERARK_PASSWORD") or prompt(
                "CyberArk service user password: ", is_password=True
            )
            response = requests.post(
                f"https://{id_tenant}.cyberark.cloud/oauth2/platformtoken",
                data={
                    "grant_type": "client_credentials",
                    "client_id": client_id,
                    "client_secret": client_secret,
                },
                timeout=self.TIMEOUT,
            )
            if response.status_code != 200:
                print_formatted_text(
                    HTML(
                        f"OAuth2 authorization token request <ansired>failed</ansired> with status code <b>{response.status_code}</b>"
                    )
                )
                return
            access_token = response.json()["access_token"]
            authorization_token = f"Bearer {access_token}"
        else:
            # CyberArk self-hosted PVWA uses a logon API to authenticate
            login_type = environ.get("KEEPER_CYBERARK_LOGON_TYPE") or prompt(
                "CyberArk logon type (Cyberark, LDAP, RADIUS or Windows): "
            )
            username = environ.get("KEEPER_CYBERARK_USERNAME") or prompt("CyberArk username: ")
            password = environ.get("KEEPER_CYBERARK_PASSWORD") or prompt("CyberArk password: ", is_password=True)
            response = requests.post(
                self.get_url(pvwa_host, "logon").format(type=login_type),
                json={"username": username, "password": password},
                timeout=self.TIMEOUT,
                verify=False,
            )
            if response.status_code != 200:
                print_formatted_text(
                    HTML(f"CyberArk Log on <ansired>failed</ansired> with status code <b>{response.status_code}</b>")
                )
                return
            authorization_token = response.text.strip('"')
        print_formatted_text(HTML("Log on <ansigreen>successful</ansigreen>"))
        # Get a list of safes, either from a file, the environment variable KEEPER_CYBERARK_SAFES, or from the API
        safes_file = environ.get("KEEPER_CYBERARK_SAFES_PATH", "safes.txt")
        if path.isfile(safes_file):
            with open(safes_file, "r", encoding="utf-8") as f:
                safes = [line.strip() for line in f if line.strip()]
                if len(safes) == 0:
                    print_formatted_text(HTML(f"Safes file <ansired>{safes_file}</ansired> is empty"))
                    return
                print_formatted_text(HTML(f"Safes from file <i>{safes_file}</i>: <b>{', '.join(safes)}</b>"))
        elif "KEEPER_CYBERARK_SAFES" in environ:
            safes = [x.strip() for x in environ.get("KEEPER_CYBERARK_SAFES").split(",") if x.strip()]
            print_formatted_text(HTML(f"Safes from environment variable KEEPER_CYBERARK_SAFES: <b>{', '.join(safes)}</b>"))
        else:
            safes = [
                x.strip()
                for x in prompt(
                    "CyberArk safes as a comma-separated list (leave empty to get safes from the server): "
                ).split(",")
                if x.strip()
            ]
            if len(safes) == 0:
                print_formatted_text(HTML("Getting safes from the server..."))
                response = self.get_response(self.get_url(pvwa_host, "safes"), authorization_token, {})
                if response.status_code != 200:
                    print_formatted_text(
                        HTML(
                            f"Getting safes from server {pvwa_host} <ansired>failed</ansired> with status <b>{response.status_code}</b>"
                        )
                    )
                    return
                safes = [x["safeName"] for x in response.json().get("value", [])]
                if len(safes) == 0:
                    print_formatted_text(HTML(f"No Safes on server <ansired>{pvwa_host}</ansired>"))
                    return
                print_formatted_text(HTML(f"Safes: <b>{', '.join(safes)}</b>"))
        # Get the accounts out of each safe
        for safe in safes:
            sleep(self.DELAY)
            response = self.get_response(
                self.get_url(pvwa_host, "accounts"), authorization_token, query_params | {"filter": f"safeName eq {safe}"}
            )
            count = response.json().get("count", 0)
            if count == 0:
                print_formatted_text(HTML(f"<ansiyellow>No accounts in safe {safe}</ansiyellow>"))
                continue
            accounts = response.json().get("value", [])
            print_formatted_text(
                HTML(f"Importing <b>{len(accounts)}</b> accounts from safe {safe}:\n"),
                tabulate([{"ID": x["id"], "Safe": x["safeName"], "Account": x["name"]} for x in accounts], headers="keys"),
                end="\n\n",
            )
            with ProgressBar() as pb:
                skip_all = {}
                skipped_accounts = []
                for r in pb(accounts, total=len(accounts)):
                    folder = SharedFolder()
                    folder.domain = r["safeName"]
                    record = Record()
                    record.folders = [folder]
                    record.title = re.sub(rf"^.*{re.escape(r['platformId'])}[\-_ ]", "", r["name"])
                    record.type = "Password"
                    if "userName" in r:
                        record.type = "login"
                        record.login = r["userName"]
                        if "address" in r:
                            record.type = "serverCredentials"
                            if r["platformAccountProperties"].get("LogonDomain"):
                                record.login = r["platformAccountProperties"]["LogonDomain"] + "\\" + r["userName"]
                    if "address" in r:
                        record.fields.append(RecordField("host", value={"hostName": r["address"]}))
                    if r["platformAccountProperties"].get("URL"):
                        record.title = r["platformAccountProperties"]["ItemName"]
                        record.login_url = r["platformAccountProperties"]["URL"]
                    retry = True
                    while retry is True:
                        response = requests.post(
                            self.get_url(pvwa_host, "account_password").format(account_id=r["id"]),
                            headers={
                                "Authorization": authorization_token,
                                "Content-Type": "application/json",
                            },
                            json={"reason": "Keeper Commander Import"},
                            timeout=self.TIMEOUT,
                            verify=True if pvwa_host.endswith(".cyberark.cloud") else False,
                        )
                        if response.status_code == 200:
                            record.password = response.text.strip('"')
                            retry = False
                            yield record
                        elif 400 <= response.status_code <= 500:
                            error = response.json()
                            if error.get('ErrorCode') in skip_all:
                                retry = False
                            else:
                                retry = button_dialog(
                                    title=f"{HTTPStatus(response.status_code).phrase} ({response.status_code})",
                                    text=HTML(
                                        "Error "
                                        f"{error.get('ErrorCode')}: <ansired>{error.get('ErrorMessage')}</ansired>\n"
                                        "Account "
                                        f"<i>{r['name']}</i> with ID <i>{r['id']}</i> in Safe <i>{r['safeName']}</i>"
                                    ),
                                    buttons=[("Retry", True), ("Skip", False), ("Skip All", None)],
                                    style=Style.from_dict({"dialog": "bg:ansiblack"}),
                                ).run()
                                if retry is None:
                                    skip_all[error.get('ErrorCode')] = True
                                    retry = False
                            if retry is False:
                                skipped_accounts.append(
                                    {
                                        "ID": r["id"],
                                        "Safe": r["safeName"],
                                        "Account": r["name"],
                                        "Status": response.status_code,
                                        "Error": error.get("ErrorCode"),
                                        "Message": error.get("ErrorMessage"),
                                    }
                                )
                        else:
                            print_formatted_text(HTML("\nImport <ansired>aborted</ansired>"))
                            return
                print_formatted_text(HTML(f"\nImported safe <b>{safe}</b>"))
                if len(skipped_accounts) > 0:
                    print_formatted_text(
                        HTML(f"\nSkipped <b>{len(skipped_accounts)}</b> Accounts:\n"),
                        tabulate(skipped_accounts, headers="keys"),
                        end="\n\n"
                    )
        print_formatted_text(HTML("\nImport <ansigreen>completed</ansigreen>"))
