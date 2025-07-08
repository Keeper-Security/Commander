import re
from http import HTTPStatus
from os import environ
from time import sleep
from urllib.parse import urlencode
import logging
import requests
from prompt_toolkit import HTML, print_formatted_text, prompt


from ..importer import BaseImporter, Record, RecordField


class CyberArkPortalImporter(BaseImporter):
    """CyberArk Portal Importer
    This importer allows users to import records from the CyberArk User Portal.
    Users authenticate using their (personal) CyberArk credentials then the importer
    retrieves applications and secured items data and yields them as Keeper records.
    Authentication uses the CyberArk Identity Portal API but may be redirected to an SSO provider.
    CyberArk Identity Portal API authentication is a multi-step process that may require
    entering a one-time password (OTP) or other out-of-band (OOB) authentication
    mechanisms depending on the user's security settings.

    The API documentation can be found at
    https://api-docs.cyberark.com/docs/identity-api-reference/

    Yields:
        Record: Login type Keeper Records for applications and Secure Notes for secured items data.
    """

    # Delay between requests to avoid hitting the API rate limits
    LOOP_DELAY = 0.025
    # Request timeout in seconds
    TIMEOUT = 10

    @staticmethod
    def get_url(id_tenant, endpoint):
        return f'https://{id_tenant}.id.cyberark.cloud/{endpoint.rstrip("/")}'

    def do_import(self, filename, **kwargs):
        id_tenant = re.search(r"^([A-Za-z0-9-]+)(\.id\.cyberark\.cloud)?$", filename.removeprefix("https://"))[0]
        username = environ.get("KEEPER_CYBERARK_USERNAME") or prompt("CyberArk User Portal username: ")
        response = requests.post(
            self.get_url(id_tenant, "/Security/StartAuthentication"),
            json={
                "TenantId": id_tenant,
                "Version": "1.0",
                "User": username,
            },
            timeout=self.TIMEOUT,
        )
        if response.status_code != HTTPStatus.OK:
            logging.error(f"Error starting authentication: {response.text}")
            return

        start_auth_result = response.json().get("Result")
        logging.debug(f"Authentication Result: {start_auth_result}")
        redirect = start_auth_result.get("PodFqdn")
        if redirect:
            print_formatted_text(
                HTML(
                    f"Use <ansigreen><i>{redirect.removesuffix('.id.cyberark.cloud')}</i></ansigreen> instead of <ansired>{id_tenant}</ansired> for user <i>{username}</i>."
                )
            )
            return
        idp_redirect_url = start_auth_result.get("IdpRedirectUrl")
        if idp_redirect_url:
            print_formatted_text(HTML("<ansired>Federated login</ansired> is not supported."))
            return

        password_operation = {
            "MechanismId": start_auth_result["Challenges"][0]["Mechanisms"][0]["MechanismId"],
            "Action": "Answer",
            "Answer": environ.get("KEEPER_CYBERARK_PASSWORD")
            or prompt("CyberArk Identity Portal password: ", is_password=True),
        }
        session_id = start_auth_result.get("SessionId")
        advance_auth_request = {
            "TenantId": id_tenant,
            "SessionId": session_id,
        }
        if len(start_auth_result["Challenges"]) > 1:
            challenge_mechs = list(start_auth_result["Challenges"][1]["Mechanisms"])
            # Use a batch-operation to send the password and start OOB authentication in one request
            advance_auth_request["MultipleOperations"] = [
                password_operation,
                {
                    "MechanismId": challenge_mechs[0]["MechanismId"],
                    "Action": "StartOOB",
                },
            ]
        else:
            challenge_mechs = []
            advance_auth_request |= password_operation

        logging.debug(f"Advance Authentication Request: {advance_auth_request}")
        response = requests.post(
            self.get_url(id_tenant, "/Security/AdvanceAuthentication"),
            json=advance_auth_request,
            timeout=self.TIMEOUT,
        )
        if response.status_code != HTTPStatus.OK:
            logging.error(f"Error advancing authentication: {response.text}")
            return
        advance_auth_result = response.json().get("Result")
        if not advance_auth_result.get("Summary") in ["OobPending", "LoginSuccess"]:
            logging.error(
                f"Unexpected authentication summary: {advance_auth_result.get('Summary')}, response: {response.text}"
            )
            return
        logging.debug(f"Advance Authentication Result: {advance_auth_result}")
        # Iterate through the challenge mechanisms until we get a successful login or run out of mechanisms
        while challenge_mechs and advance_auth_result.get("Summary") == "OobPending":
            response = requests.post(
                self.get_url(id_tenant, "/Security/AdvanceAuthentication"),
                json={
                    "TenantId": id_tenant,
                    "SessionId": session_id,
                    "MechanismId": challenge_mechs[0]["MechanismId"],
                    "Action": "Answer",
                    "Answer": prompt(f"Authentication code from {challenge_mechs[0]['PromptSelectMech']}: "),
                },
                timeout=self.TIMEOUT,
            )
            if response.status_code != HTTPStatus.OK:
                logging.error(f"Error advancing authentication: {response.text}")
                return
            advance_auth_result = response.json().get("Result")
            if advance_auth_result.get("Summary") != "OobPending":
                challenge_mechs = challenge_mechs[1:]
            elif advance_auth_result.get("Summary") == "LoginSuccess":
                break

        if advance_auth_result.get("Summary") != "LoginSuccess":
            logging.error(
                f"Unexpected authentication summary: {advance_auth_result.get('Summary')}, response: {response.text}"
            )
            return
        print_formatted_text(HTML("Authentication <ansigreen>successful</ansigreen>"))
        authentication_token = advance_auth_result.get("Token")
        # Get all the application data (except the password, of course) in one API call
        response = requests.post(
            self.get_url(id_tenant, "/UPRest/GetUPData"),
            headers={"Authorization": f"Bearer {authentication_token}"},
            json={},
            timeout=self.TIMEOUT,
        )
        if response.status_code != HTTPStatus.OK:
            logging.error(f"Error getting UP data: {response.text}")
            return
        apps = response.json()["Result"]["Apps"]

        if len(apps) > 0:
            print_formatted_text(HTML(f"Importing <b>{len(apps)}</b> Applications"))
            for app in apps:
                app_key = app["AppKey"]
                response = requests.post(
                    self.get_url(id_tenant, f"/UPRest/GetMCFA?appkey={app_key}"),
                    headers={
                        "Authorization": f"Bearer {authentication_token}",
                    },
                    json={},
                    timeout=self.TIMEOUT,
                )
                if response.status_code != HTTPStatus.OK:
                    logging.error(f"Error getting password for app {app_key}: {response.text}")
                    continue

                record = Record()
                record.type = "login"
                record.title = app["Name"]
                record.login_url = app["Url"]
                record.username = app["Username"]
                record.password = response.json()["Result"]["p"]
                if app["IsTotpSet"]:
                    record.notes = "The original CyberArk Application included a TOTP that was not imported."
                yield record
                sleep(self.LOOP_DELAY)

        response = requests.post(
            self.get_url(id_tenant, "/UPRest/GetSecuredItemsData"),
            headers={"Authorization": f"Bearer {authentication_token}"},
            json={},
            timeout=self.TIMEOUT,
        )
        if response.status_code != HTTPStatus.OK:
            logging.error(f"Error getting secured items data: {response.text}")
            return
        secured_items = response.json()["Result"]["SecuredItems"]

        if len(secured_items) > 0:
            print_formatted_text(HTML(f"Importing <b>{len(secured_items)}</b> Secured Items"))
            for item in secured_items:
                item_key = item["ItemKey"]
                response = requests.post(
                    self.get_url(id_tenant, f"/UPRest/GetCredsForSecuredItem?sItemKey={item_key}"),
                    headers={"Authorization": f"Bearer {authentication_token}"},
                    json={},
                    timeout=self.TIMEOUT,
                )
                if response.status_code != HTTPStatus.OK:
                    print_formatted_text(
                        HTML(f"<ansired>Error getting notes for item {item_key}: <i>{response.text}</i></ansired>")
                    )
                    continue
                record = Record()
                record.type = "encryptedNotes"
                record.title = item["Name"]
                record.fields.append(RecordField(type="note", value=response.json()["Result"]["n"]))
                yield record
                sleep(self.LOOP_DELAY)

        print_formatted_text(HTML("Import <ansigreen>complete</ansigreen>"))
