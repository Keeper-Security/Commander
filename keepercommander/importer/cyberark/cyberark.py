import re
import requests
from http import HTTPStatus
from prompt_toolkit import HTML, print_formatted_text, prompt
from prompt_toolkit.shortcuts import button_dialog, ProgressBar
from prompt_toolkit.styles import Style
from tabulate import tabulate
from urllib.parse import parse_qsl


from ..importer import BaseImporter, SharedFolder, Record, RecordField


class CyberArkImporter(BaseImporter):
    # CyberArk REST API endpoints (relative to the base URL)
    ENDPOINTS = {
        "accounts": "Accounts",
        "account_password": "Accounts/{account_id}/Password/Retrieve",
        "logon": "Auth/{type}/Logon",
    }
    # Request timeout in seconds
    TIMEOUT = 10

    @classmethod
    def get_url(cls, pvwa_host, endpoint):
        return f"https://{pvwa_host}/PasswordVault/API/{cls.ENDPOINTS[endpoint]}"

    def get_accounts(self, pvwa_host, authorization_token, query_params):
        response = requests.get(
            self.get_url(pvwa_host, "accounts"),
            headers={
                "Authorization": authorization_token,
                "Content-Type": "application/json",
            },
            params=query_params,
            timeout=self.TIMEOUT,
        )
        if response.status_code == 200:
            return response
        print_formatted_text(
            HTML(f"Getting Accounts <ansired>failed</ansired> with status code <b>{response.status_code}</b>")
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
        if "limit" in query_params:
            query_params["limit"] = int(query_params["limit"])
        else:
            query_params["limit"] = 1000
        if "offset" in query_params:
            query_params["offset"] = int(query_params["offset"])
        else:
            query_params["offset"] = 0
        # CyberArk Privilege Cloud uses an OAuth2 client_credentials grant for authentication
        if pvwa_host.endswith(".cyberark.cloud"):
            pvwa_host = f"{pvwa_host.split('.')[0]}.privilegecloud.cyberark.cloud"
            id_tenant = prompt("CyberArk Identity Tenant ID: ")
            if re.match(r"^[A-Za-z]{3}\d{4}$", id_tenant):
                # Handle customized tenant ID URLs by removing the ".id" suffix
                id_tenant += ".id"
            response = requests.post(
                f"https://{id_tenant}.cyberark.cloud/oauth2/platformtoken",
                data={
                    "grant_type": "client_credentials",
                    "client_id": prompt("CyberArk service user name: "),
                    "client_secret": prompt("CyberArk service user password: ", is_password=True),
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
            response = requests.post(
                self.get_url(pvwa_host, "logon").format(
                    type=prompt("CyberArk logon type (Cyberark, LDAP, RADIUS or Windows): ")
                ),
                json={
                    "username": prompt("CyberArk username: "),
                    "password": prompt("CyberArk password: ", is_password=True),
                },
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
        while True:
            print_formatted_text(f"Listing up to {query_params['limit']} Accounts starting at {query_params['offset']}")
            response = self.get_accounts(pvwa_host, authorization_token, query_params)
            if response is None:
                print_formatted_text(HTML("<ansired>Empty response</ansired>"))
                break
            count = response.json().get("count", 0)
            if count == 0:
                print_formatted_text(HTML("<ansiyellow>No accounts found</ansiyellow>"))
                break
            accounts = response.json().get("value", [])
            if len(accounts) == 0:
                break
            print_formatted_text(HTML(f"Importing <b>{len(accounts)}</b> Accounts:\n"))
            print_formatted_text(
                tabulate(
                    [{"ID": x["id"], "Safe": x["safeName"], "Account": x["name"]} for x in accounts],
                    headers="keys"),
                end="\n\n")
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
                            if response.status_code in skip_all:
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
                                    style=Style.from_dict({"dialog": "bg:ansiblack"})
                                ).run()
                                if retry is None:
                                    skip_all[response.status_code] = True
                                    retry = False
                            if retry is False:
                                skipped_accounts.append({
                                    "ID": r["id"],
                                    "Safe": r["safeName"],
                                    "Account": r["name"],
                                    "Status": response.status_code,
                                    "Error": error.get("ErrorCode"),
                                    "Message": error.get("ErrorMessage"),
                                })
                        else:
                            print_formatted_text(HTML("\nImport <ansired>aborted</ansired>"))
                            return
            if count > len(accounts) + query_params["offset"]:
                query_params["offset"] += query_params["limit"]
            else:
                print_formatted_text(HTML("\nImport <ansigreen>completed</ansigreen>"))
                break
        if len(skipped_accounts) > 0:
            print_formatted_text(
                HTML(f"\nSkipped <b>{len(skipped_accounts)}</b> Accounts:\n"),
                tabulate(skipped_accounts, headers="keys"),
                end="\n\n"
            )
