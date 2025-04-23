import urllib3
import requests
from http import HTTPStatus
from prompt_toolkit import HTML, print_formatted_text, prompt
from prompt_toolkit.shortcuts import button_dialog, ProgressBar
from prompt_toolkit.styles import Style
from tabulate import tabulate

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


from ..importer import BaseImporter, Record, RecordField


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
            verify=True if pvwa_host.endswith(".cyberark.cloud") else False,
        )
        if response.status_code == 200:
            return response
        print_formatted_text(
            HTML(f"Getting Accounts <ansired>failed</ansired> with status code <b>{response.status_code}</b>")
        )

    def do_import(self, filename, **kwargs):
        pvwa_host = filename.rstrip("/").lstrip("https://")
        # The CyberArk API implements paging with a limit of 1000 records per page
        query_params = {"limit": 1000, "offset": 0}
        if "?" in pvwa_host:
            # Use what comes after the (optional) '?' as the search query
            pvwa_host, query_params["search"] = pvwa_host.split("?", 1)
        # CyberArk Cloud uses an OAuth2 client_credentials grant for authentication
        if pvwa_host.endswith(".cyberark.cloud"):
            pvwa_host = f"{pvwa_host.split('.')[0]}.privilegecloud.cyberark.cloud"
            tenant_id = prompt("CyberArk Identity Tenant ID: ").rstrip("/").lstrip("https://").split(".")[0]
            response = requests.post(
                f"https://{tenant_id}.id.cyberark.cloud/oauth2/platformtoken",
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
                break
            count = response.json().get("count", 0)
            limit = count if count < query_params["limit"] else query_params["limit"]
            accounts = response.json().get("value", [])
            print_formatted_text(HTML(f"Importing <b>{limit}</b> Accounts:\n"))
            print_formatted_text(
                tabulate(
                    [{"ID": x["id"], "Safe": x["safeName"], "Account": x["name"]} for x in accounts],
                    headers="keys"),
                end="\n\n")
            with ProgressBar() as pb:
                skip_all = {}
                skipped_accounts = []
                for r in pb(accounts, total=limit):
                    record = Record()
                    record.title = r["name"]
                    record.type = "Password"
                    if hasattr(r, "userName"):
                        record.type = "login"
                        record.login = r["userName"]
                    if hasattr(r, "address"):
                        record.type = "serverCredentials"
                        record.fields.append(RecordField(type="host", value={"hostName": r["address"]}))
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
                            if response.status_code in skip_all:
                                retry = False
                            else:
                                retry = button_dialog(
                                    title=f"{HTTPStatus(response.status_code).phrase} ({response.status_code})",
                                    text=HTML(
                                        "Getting password for Account "
                                        f"<i>{r['name']}</i> with ID <i>{r['id']}</i> in Safe <i>{r['safeName']}</i>"
                                    ),
                                    buttons=[("Retry", True), ("Skip", False), ("Skip All", None)],
                                    style=Style.from_dict({"dialog": "bg:ansiblack"}
                                )).run()
                                if retry is None:
                                    skip_all[response.status_code] = True
                                    retry = False
                            if retry is False:
                                skipped_accounts.append(r)
                        else:
                            print_formatted_text(HTML("\nImport <ansired>aborted</ansired>"))
                            return
            if count > query_params["limit"]:
                query_params["offset"] += query_params["limit"]
            else:
                print_formatted_text(HTML("\nImport <ansigreen>completed</ansigreen>"))
                break
        if len(skipped_accounts) > 0:
            print_formatted_text(
                HTML(f"\nSkipped <b>{len(skipped_accounts)}</b> Accounts:\n"),
                tabulate(
                    [{"ID": x["id"], "Safe": x["safeName"], "Account": x["name"]} for x in skipped_accounts],
                    headers="keys"),
                end="\n\n")
