import getpass
import urllib3
import requests

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


from ..importer import BaseImporter, Record, RecordField


class CyberArkImporterException(BaseException):
    def __init__(self, message, response):
        self.message = f"{message}: status {response.status_code}: {response.text}"
        super().__init__(self.message)


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

    def do_import(self, filename, **kwargs):
        # The CyberArk API implements paging with a limit of 1000 records per page
        query_params = {"limit": 1000, "offset": 0}
        if "?" in filename:
            # Use what comes after the (optional) '?' as the search query
            pvwa_host, query_params["search"] = filename.split("?", 1)
        else:
            pvwa_host = filename
        # CyberArk Cloud uses an OAuth2 client_credentials grant for authentication
        if pvwa_host.endswith(".cyberark.cloud"):
            tenant_id = input("CyberArk Identity Tenant ID: ").rstrip(".id")
            response = requests.post(
                f"https://{tenant_id}.id.cyberark.cloud/oauth2/platformtoken",
                data={
                    "grant_type": "client_credentials",
                    "client_id": input("CyberArk service user name: "),
                    "client_secret": getpass.getpass(
                        "CyberArk service user password: "
                    ),
                },
                timeout=self.TIMEOUT,
            )
            if response.status_code != 200:
                raise CyberArkImporterException(
                    "OAuth2 client_credentials request failed", response
                )
            access_token = response.json()["access_token"]
            authorization_token = f"Bearer {access_token}"
        else:
            response = requests.post(
                self.get_url(pvwa_host, "logon").format(
                    type=input(
                        "CyberArk logon type (Cyberark, LDAP, RADIUS or Windows): "
                    )
                ),
                json={
                    "username": input("CyberArk username: "),
                    "password": getpass.getpass("CyberArk password: "),
                },
                timeout=self.TIMEOUT,
                verify=False,
            )
            if response.status_code != 200:
                raise CyberArkImporterException("Log on failed", response)
            authorization_token = response.text.strip('"')
        response = requests.get(
            self.get_url(pvwa_host, "accounts"),
            headers={
                "Authorization": authorization_token,
                "Content-Type": "application/json",
            },
            params=query_params,
            timeout=self.TIMEOUT,
            verify=False,
        )
        if response.status_code != 200:
            raise CyberArkImporterException("Getting Accounts failed", response)
        while True:
            count = response.json().get("count", 0)
            for r in response.json().get("value", []):
                record = Record()
                record.type = "serverCredentials"
                record.title = r["name"]
                record.login = r["userName"]
                record.fields.append(
                    RecordField(type="host", value={"hostName": r["address"]})
                )
                response = requests.post(
                    self.get_url(pvwa_host, "account_password").format(
                        account_id=r["id"]
                    ),
                    headers={
                        "Authorization": authorization_token,
                        "Content-Type": "application/json",
                    },
                    timeout=self.TIMEOUT,
                    verify=False,
                )

                if response.status_code != 200:
                    raise CyberArkImporterException(
                        "Getting Account Password failed", response
                    )
                record.password = response.text.strip('"')
                yield record
            if count <= query_params["limit"]:
                break
            query_params["offset"] += query_params["limit"]
            response = requests.get(
                self.get_url(pvwa_host, "accounts"),
                headers={
                    "Authorization": authorization_token,
                    "Content-Type": "application/json",
                },
                params=query_params,
                timeout=self.TIMEOUT,
                verify=False,
            )
            if response.status_code != 200:
                raise CyberArkImporterException("Getting Accounts failed", response)
