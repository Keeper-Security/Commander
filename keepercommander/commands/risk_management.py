import argparse
import datetime
import json

from . import base, enterprise_common, audit_alerts
from .. import api
from ..proto import rmd_pb2


benchmark_mapping = {
        "SB_CREATE_AT_LEAST_TWO_KEEPER_ADMINISTRATORS":
        {
            "title": "Create at least two Keeper Administrators",
            "description": "Keeper Administrators hold the encryption keys used to access the Admin Console, provision users, manage enforcement policies and perform day to day user administration.\n\nThe Keeper Administrator role should have at least two users in that role. We strongly recommend adding a secondary admin to this role in case one account is lost, the person leaves the organization or the employee is terminated. The Keeper support team cannot elevate a user to an administrative role or reset an administrator's Master Password, by design.\n\nBy design, if all of the Keeper Administrators lose access, Keeper's support team cannot elevate privilege, and Keepers support team cannot approve SSO user devices. Make sure you have a break glass account with root level Keeper Administrator access."
            },
    "SB_ENSURE_TWO_FACTOR_AUTHENTICATION_ADMIN_USERS":
  {
    "title": "Enforce 2FA on the Keeper Administrator role",
    "description": "Keeper Administrators have elevated privilege in the platform and must be protected against both outside attacks, identity provider attacks and insider attack vectors. Ensure that the Keeper Administrator role and any other role with administrative privilege is enforcing the use of 2FA.\n\nIf an admin is logging in to Keeper with an SSO provider, we still recommend adding the additional layer of 2FA on the Keeper side for any administrative role. This protects against IdP account takeover or other insider threats."
  },
    "SB_ENSURE_OUTSIDE_SSO_ADMINISTRATOR_EXISTS":
  {
    "title": "Ensure an administrator exists outside of SSO",
    "description": "Keeper SSO Connect Cloud provides customers with the ability to provision and authenticate users with their preferred SAML 2.0 identity provider.\n\nWhile Keeper supports the ability for admins to login to the Keeper Admin Console with SSO, it is important that at least one Admin account is able to login to Keeper with a Master Password. This is because a situation could occur in which all admins rely on SSO, and there may be no admins to approve a new device. Or, the SSO provider could have an outage which then locks everyone out. We recommend creating an Admin \"service account\" which uses a strong Master Password, 2FA and (optionally) IP AllowListing to optimally lock down this account.\n\nIn the situation where all admins use SSO, and all admins are on new devices (unable to approve them) Keeper support will not be able to help recover. By design, Keeper is a zero knowledge platform and our support team has no ability to approve SSO-enabled devices, or recover Device-Encrypted Data Keys for users."
  },
    "SB_REDUCE_ADMINISTRATOR_PRIVILEGE":
  {
    "title": "Reduce administrator privilege",
    "description": "Keeper's role enforcement policies allow customers to create administrative roles within nodes and sub-nodes. It is important to always ensure least privilege for administrators.\n\nReduce the total number of Admins to the minimum required to operate efficiently.\n\nReduce privilege within Administrative roles. For example, if an Admin does not require the ability to manage roles, remove that privilege.\n\nDon't leave old admin accounts from former employees in an locked state longer than necessary to transfer the contents of the vault."
  },
    "SB_LOCK_DOWN_SSO_PROVIDER":
  {
    "title": "Lock down your SSO provider",
    "description": "If you are integrating Keeper with your SSO identity provider, ensure that your IdP is locked down with MFA policies and reduced privilege. Follow the guidance and best practices of your identity provider to ensure that administrative accounts are minimized with the least amount of privilege necessary to perform their jobs.\n\nThe https://docs.keeper.io/v/sso-connect-cloud/device-approvals/automator provides Cloud SSO-enabled users with a frictionless experience when accessing their vault on a new or unrecognized device. While this improves the user experience, it also requires that your SSO identity provider is protected against unauthorized access. If you enable the Keeper Automator service, you are placing full trust in the identity provider authentication and the user provisioning process. For additional security, the Automator service can limit automated approvals to specific IP ranges, or it can be left disabled completely to force users to manually approve new devices."
  },
    "SB_DISABLE_ACCOUNT_RECOVERY":
  {
    "title": "Disable account recovery when appropriate",
    "description": "As with any SaaS platform, account recovery provides end-users with a route to restore access to their account, if the primary authentication methods are lost or forgotten. In Keeper, by default the user has an ability to configure a Recovery Phrase - a simple, auto-generated set of 24 words that can be used to restore access to their Keeper Vault. The recovery phrase encrypts the user's Data Key using a key derivation similar to the Master Password method.\n\nIf you are deploying to users with a single sign-on product like Azure or Okta, account recovery may not be necessary or warranted, since authentication is delegated to your identity provider. Therefore, it is best to simply not have account recovery as an option, if this is acceptable to your users.\n\nTo disable account recovery, visit the <b>Role</b> > <b>Enforcement Policies</b> > <b>Account Settings</b> > select \"<b>Disable Recovery Phrase for account recovery</b>\".\n\nAccount recovery can be enabled if the affected users store their Recovery Phrase in a safe location."
  },
    "SB_ENFORCE_STRONG_MASTER_PASSWORD":
  {
    "title": "Enforce a strong Master Password",
    "description": "For users who login with a Master Password, the key to decrypt and encrypt the Data Key is derived from the user's Master Password using the password-based key derivation function (PBKDF2), with 1,000,000 iterations by default. After the user types their Master Password, the key is derived locally and then unwraps the Data Key. After the Data Key is decrypted, it is used to unwrap the individual record keys and folder keys. The Record Key then decrypts each of the stored record contents locally.\n\nKeeper implements several mitigations against unauthorized access, device verification, throttling and other protections in the Amazon AWS environment. Enforcing a strong Master Password complexity significantly reduces any risk of offline brute force attack on a user's encrypted vault.\n\nThe National Institute of Standards and Technology (NIST) provides password guidelines in: https://pages.nist.gov/800-63-3/sp800-63b.html The guidelines promote a balance between usability and security; Or in other words, passwords should be easy to remember but hard to guess. The NIST instruction recommends an eight character minimum but a higher value will ultimately result in a harder to guess/crack password. Keeper enforces at least 12 characters. We recommend increasing this to 16 or more.\n\nPassword complexity can be configured on a per role-basis. See the https://docs.keeper.io/v/enterprise-guide/roles#master-password-complexity enforcement setting in the guide."
  },
  "SB_ENSURE_TWO_FACTOR_AUTHENTICATION_FOR_END_USERS":
  {
    "title": "Enforce Two-Factor Authentication for end-users",
    "description": "Two-Factor Authentication (2FA), also commonly referred to as multi-factor authentication (MFA), adds an additional layer of security to access the vault. The first layer is something your users know; their Master Password or SSO. The second layer is something they have. It can be either their mobile device (SMS text or a TOTP application) or by using a hardware device such as YubiKey or Google Titan key.\n\nWhile Keeper's cloud infrastructure implements several mitigations against brute force attack, adding a second means of authentication will makes it considerably more difficult for an attacker to gain access a user's vault. Using a role based enforcement can ensure all users of the enterprise are mandated to configure 2FA on their vault account.\n\nSSO-enabled users should ensure 2FA is configured with their IdP at a minimum. Keeper checks for a signed assertion from the identity provider during SSO authentication. For additional security, 2FA can be enabled on the Keeper side in addition to the IdP.\n\nTo set up 2FA See the section in the guide: https://docs.keeper.io/v/enterprise-guide/two-factor-authentication."
  },
  "SB_CONFIGURE_IP_ALLOWLISTING":
  {
    "title": "Configure IP Allowlisting",
    "description": "To prevent users from accessing their work vault outside of approved locations and networks, administrators should consider activating IP Address Allowlisting.  This is a role-based enforcement setting that designated users can only access their vaults when their device is on an approved network.\n\nAt minimum, users with Administrative privileges in Keeper should be locked down to specific IPs or IP ranges. This prevents malicious insider attacks as well as identity provider takeover attack vectors. If this is not possible, ensure that MFA is enforced.\n\nVisit the section on https://docs.keeper.io/v/enterprise-guide/ip-allow-keeper for more information on configuring roles to include this feature."
  },
  "SB_ENABLE_ACCOUNT_TRANSFER_POLICY":
  {
    "title": "Enable Account Transfer policy when necessary",
    "description": "Account Transfer provides a mechanism for a designated administrator to recover the contents of a user's vault, in case the employee suddenly leaves or is terminated. This is an optional feature that must be configured by the Keeper Administrator during the initial deployment phase of the Keeper rollout, because it requires specific steps to escrow the user's encryption keys.\n\nFor step by step details visit the https://docs.keeper.io/v/enterprise-guide/account-transfer-policy.\n\nThe Account Transfer policy is recommended if users are authenticating with a Master Password, and if the enterprise has concerns regarding the loss of specific user vaults.\n\nThe Account Transfer policy gives admins with the assigned privilege to perform transfers of a Keeper vault for their managed users. If you have users (such as C-level executives or root-level admins) that <b>do not</b> want their vault transferred under any circumstances, these users can be placed into a role that does not have the transfer policy enabled."
  },
  "SB_CREATE_ALERTS":
  {
    "title": "Create alerts",
    "description": "Keeper's Advanced Reporting System provides built-in Alerting capabilities that will notify users and Administrators for important events. As a best practice, we have https://docs.keeper.io/v/enterprise-guide/recommended-alerts that can be configured by the Keeper Administrator. Alerts should be enabled on key administrative events to notify any suspicious activity coming from both external and insider threats."
  },
  "SB_PREVENT_INSTALLATION_OF_UNTRUSTED_EXTENSIONS":
  {
    "title": "Prevent installation of untrusted extensions",
    "description": "As a general security practice, we recommend that Enterprise customers limit the ability of end-users to install unapproved third-party browser extensions. Browser extensions with elevated permissions could have the ability to access any information within any website or browser-based application. Please refer to your device management software to ensure that Keeper is allowed, and unapproved extensions are blocked or removed."
  },
    "SB_DEPLOY_ACROSS_ENTIRE_ORGANIZATION":
  {
    "title": "Deploy across your entire organization",
    "description": "To protect all of your users across all of their devices, applications and websites, Keeper should be deployed to all users in your entire organization who handle privileged credentials. Any administrator or privileged user who does not use a secure password manager can put your organization at risk."
  },
    "SB_DISABLE_BROWSER_PASSWORD_MANAGERS":
  {
    "title": "Disable built-in browser password managers",
    "description": "Modern browsers typically have their own versions of a password manager. In addition to being less robust and secure than Keeper, these password managers can conflict with Keeper, causing login issues or even security contradictions.  To prevent conflicts and harden security, Keeper recommends disabling built-in browser password managers."
  },
    "SB_ENFORCE_LEAST_PRIVILEGE_POLICY":
  {
    "title": "Enforce least privilege policy on managed devices",
    "description": "Apply least privilege access controls for all managed devices to minimize attack surface and prevent unauthorized system access. Keeper Endpoint Privilege Manager “Least Privilege” policy reduces the risk of lateral movement, privilege escalation, and data breaches while supporting regulatory compliance frameworks like SOC 2, NIST, and ISO 27001."
  }
}

class RiskManagementReportCommand(base.GroupCommand):
    def __init__(self):
        super().__init__()
        self.register_command('enterprise-stat', RiskManagementEnterpriseStatCommand(), 'Show Risk Management recent login count', 'es')
        self.register_command('enterprise-stat-details', RiskManagementEnterpriseStatDetailsCommand(), 'Gets the recent login count (users who logged in the last 30 days) '
                              'and the number of users who have at least one record in their Vault', 'esd')
        self.register_command('security-alerts-summary', RiskManagementSecurityAlertsSummaryCommand(), 'Gets the summary of events that happened in the last 30 days with '
                              'a comparison to the previous 30 days.', 'sas')
        self.register_command('security-alerts-detail', RiskManagementSecurityAlertDetailCommand(), 'Gets the details of event that happened in the last 30 days with a '
                              'comparison to the previous 30 days. The response is paginated with a page size of 10000 users.', 'sad')
        self.register_command('security-benchmarks-get', RiskManagementSecurityBenchmarksGetCommand(), 'Get the list of security benchmark set for the calling enterprise.', 'sbg')
        self.register_command('security-benchmarks-set', RiskManagementSecurityBenchmarksSetCommand(), 'Set a list of security benchmark. Corresponding audit events will be logged.', 'sbs')
        #Backward compatibility
        self.register_command('user', RiskManagementEnterpriseStatDetailsCommand(), 'Show Risk Management User report', 'u')
        self.register_command('alert', RiskManagementSecurityAlertsSummaryCommand(), 'Show Risk Management Alert report', 'a')


rmd_enterprise_stat_parser = argparse.ArgumentParser(prog='risk-management enterprise-stat', description='Risk management enterprise stat', parents=[base.report_output_parser])

rmd_enterprise_stat_detail_parser = argparse.ArgumentParser(prog='risk-management enterprise-stat-details', description='Risk management enterprise stat details', parents=[base.report_output_parser])

rmd_security_alerts_summary_parser = argparse.ArgumentParser(prog='risk-management security-alerts-summary', description='Risk management security alerts summary', parents=[base.report_output_parser])

rmd_security_alerts_detail_parser = argparse.ArgumentParser(prog='risk-management security-alerts-detail', description='Risk management security alerts detail', parents=[base.report_output_parser])
rmd_security_alerts_detail_parser.add_argument('aet', nargs='?', type=str, action='store', help='show the details for audit event type.')

rmd_security_benchmarks_get_parser = argparse.ArgumentParser(prog='risk-management security-benchmarks-get', description='Risk management get security benchmarks', parents=[base.report_output_parser])
rmd_security_benchmarks_get_parser.add_argument('--description', dest='description', action='store_true', help='Add description.')

rmd_security_benchmarks_set_parser = argparse.ArgumentParser(prog='risk-management security-benchmarks-set', description='Risk management set security benchmarks', parents=[base.report_output_parser])
rmd_security_benchmarks_set_parser.add_argument('fields', nargs='*', type=str, action='store', help='fields to set for benchmark results.')

class RiskManagementEnterpriseStatDetailsCommand(enterprise_common.EnterpriseCommand):
    def get_parser(self):
        return rmd_enterprise_stat_detail_parser

    def execute(self, params, **kwargs):
        user_lookup = {x['enterprise_user_id']: x['username'] for x in params.enterprise.get('users', [])}
        rows = []
        header = ['username', 'last_logged_in', 'has_records']
        done = False
        last_updated = 0
        t_last_updated = 0
        t_last_id = 0
        while not done:
            rq = rmd_pb2.EnterpriseStatDetailsRequest()
            if last_updated > 0:
                rq.lastUpdated = last_updated
            if t_last_id > 0:
                rq.continuationToken.enterpriseUserId = t_last_id
            if t_last_updated > 0:
                rq.continuationToken.lastUpdated = t_last_updated

            rs = api.communicate_rest(params, rq, 'rmd/get_enterprise_stat_details', rs_type=rmd_pb2.EnterpriseStatDetailsResponse)
            done = rs.hasMore is False
            if not done:
                last_updated = rs.lastUpdated
                t_last_updated = rs.continuationToken.lastUpdated
                t_last_id = rs.continuationToken.enterpriseUserId
            for detail in rs.enterpriseStatDetails:
                enterprise_user_id = detail.enterpriseUserId
                username = user_lookup.get(enterprise_user_id) or str(enterprise_user_id)
                if detail.lastLoggedIn > 0:
                    last_logged_in = datetime.datetime.fromtimestamp(detail.lastLoggedIn // 1000)
                else:
                    last_logged_in = None

                rows.append([username, last_logged_in, detail.hasRecords])

        if kwargs.get('format') != 'json':
            header = [base.field_to_title(x) for x in header]

        return base.dump_report_data(rows, headers=header, fmt=kwargs.get('format'), filename=kwargs.get('output'))


class RiskManagementSecurityAlertsSummaryCommand(enterprise_common.EnterpriseCommand):
    def get_parser(self):
        return rmd_security_alerts_summary_parser

    def execute(self, params, **kwargs):
        audit_alerts.AuditSettingMixin.load_settings(params, False)
        event_lookup = {x[0]: x[1] for x in audit_alerts.AuditSettingMixin.EVENT_TYPES}
        fmt = kwargs.get('format')
        if fmt == 'json':
            header = ['event', 'event_occurrences', 'last_events', 'unique_users', 'last_users']
        else:
            header = ['event', 'event_occurrences', 'last_events', 'unique_users', 'last_users', 'event_trend', 'user_trend']
        rows = []
        rs = api.communicate_rest(params, None, 'rmd/get_security_alerts_summary', rs_type=rmd_pb2.SecurityAlertsSummaryResponse)
        for sas in rs.securityAlertsSummary:
            event_id = sas.auditEventTypeId
            if event_id in event_lookup:
                event_id = event_lookup[event_id]
            event_count = sas.currentCount
            prev_event_count = sas.previousCount
            user_count = sas.currentUserCount
            prev_user_count = sas.previousUserCount

            if event_count != prev_event_count:
                if prev_event_count > 0 and event_count > 0:
                    rate = (event_count - prev_event_count) / prev_event_count
                    event_trend = '[   ↗ ]' if rate > 0 else '[ ↘   ]'
                elif prev_event_count > 0:
                    event_trend = '[    ↑]'
                else:
                    event_trend = '[↓    ]'
            else:
                event_trend = '[  -  ]'

            if user_count != prev_user_count:
                if prev_event_count > 0 and user_count > 0:
                    rate = (user_count - prev_user_count) / prev_user_count
                    user_trend = '[   ↗ ]' if rate > 0 else '[ ↘   ]'
                elif prev_event_count > 0:
                    user_trend = '[    ↑]'
                else:
                    user_trend = '[↓    ]'
            else:
                user_trend = '[  -  ]'

            if fmt == 'json':
                rows.append([event_id, event_count, prev_event_count, user_count, prev_user_count])
            else:
                rows.append([event_id, event_count, prev_event_count, user_count, prev_user_count, event_trend, user_trend])

        if kwargs.get('format') != 'json':
            header = [base.field_to_title(x) for x in header]

        return base.dump_report_data(rows, headers=header, fmt=kwargs.get('format'), filename=kwargs.get('output'))


class RiskManagementEnterpriseStatCommand(enterprise_common.EnterpriseCommand):
    def get_parser(self):
        return rmd_enterprise_stat_parser

    def execute(self, params, **kwargs):
        rs = api.communicate_rest(params, None, 'rmd/get_enterprise_stat', rs_type=rmd_pb2.EnterpriseStat)
        fmt = kwargs.get('format')
        #filename=kwargs.get('output')
        if fmt == 'json':
            print(json.dumps({
                "users_logged_recent": rs.usersLoggedRecent,
                "users_has_records":  rs.usersHasRecords,
                }))
        else:
            print('{0:>20s}:'.format('Users Enterprise Stat'))
            print('{0:>20s}: {1:<20d}'.format('Logged in', rs.usersLoggedRecent))
            print('{0:>20s}: {1:<20d}'.format('Has records', rs.usersHasRecords))


class RiskManagementSecurityAlertDetailCommand(enterprise_common.EnterpriseCommand):
    def get_parser(self):
        return rmd_security_alerts_detail_parser

    def execute(self, params, **kwargs):
        audit_alerts.AuditSettingMixin.load_settings(params, False)
        event_lookup = {x[1]: x[0] for x in audit_alerts.AuditSettingMixin.EVENT_TYPES}
        user_lookup = {x['enterprise_user_id']: x['username'] for x in params.enterprise.get('users', [])}
        request = rmd_pb2.SecurityAlertsDetailRequest()
        aet = kwargs.get('aet')
        aetid = event_lookup.get(aet, 0)
        if aetid < 1:
            raise ValueError(f'Invalid aetid {aetid}: valid aetid > 0')
        request.auditEventTypeId = aetid
        done = False
        header = [
                'enterprise_user_id',
                'current_count',
                'previous_count',
                'last_occurrence',
                ]
        out_format = kwargs.get('format')
        if out_format != 'json':
            header = [base.field_to_title(x) for x in header]
        rows = []
        while not done:
            response = api.communicate_rest(params, request, 'rmd/get_security_alerts_detail', rs_type=rmd_pb2.SecurityAlertsDetailResponse)
            done = not response.hasMore
            request.continuationToken = response.continuationToken
            for node in response.securityAlertDetails:
                enterprise_user_id = node.enterpriseUserId
                username = user_lookup.get(enterprise_user_id) or str(enterprise_user_id)
                last_occurrence = None
                if node.lastOccurrence and node.lastOccurrence > 0:
                    last_occurrence = datetime.datetime.fromtimestamp(node.lastOccurrence // 1000)
                rows.append([
                    username,
                    node.currentCount,
                    node.previousCount,
                    last_occurrence,
                    ])
        return base.dump_report_data(rows, headers=header, fmt=out_format, filename=kwargs.get('output'))


class RiskManagementSecurityBenchmarksGetCommand(enterprise_common.EnterpriseCommand):
    def get_parser(self):
        return rmd_security_benchmarks_get_parser

    def execute(self, params, **kwargs):
        is_description = kwargs.get('description')
        header = [
                'id',
                'status',
                'last_updated',
                'auto_resolve',
                'title',
                ]
        if is_description:
            header.append("description")
        out_format = kwargs.get('format')
        if out_format != 'json':
            header = [base.field_to_title(x) for x in header]
        rows = []
        response = api.communicate_rest(params, None, 'rmd/get_security_benchmarks', rs_type=rmd_pb2.GetSecurityBenchmarksResponse)
        for node in response.enterpriseSecurityBenchmarks:
            last_updated = None
            if node.lastUpdated and node.lastUpdated > 0:
                last_updated = datetime.datetime.fromtimestamp(node.lastUpdated // 1000)
            name = rmd_pb2.SecurityBenchmark.Name(node.securityBenchmark)
            row = [
                name,
                rmd_pb2.SecurityBenchmarkStatus.Name(node.securityBenchmarkStatus),
                last_updated,
                node.autoResolve,
                benchmark_mapping.get(name, {}).get("title", ""),
                ]
            if is_description:
                row.append(benchmark_mapping.get(name, {}).get("description", ""))
            rows.append(row)
        return base.dump_report_data(rows, headers=header, fmt=out_format, filename=kwargs.get('output'))


class RiskManagementSecurityBenchmarksSetCommand(enterprise_common.EnterpriseCommand):
    def get_parser(self):
        return rmd_security_benchmarks_set_parser

    def execute(self, params, **kwargs):
        request = rmd_pb2.SetSecurityBenchmarksRequest()
        fields = kwargs.get('fields', [])
        for field in fields:
            k, v = field.strip().split(":")
            esb = rmd_pb2.EnterpriseSecurityBenchmark()
            esb.securityBenchmark = rmd_pb2.SecurityBenchmark.Value(k)
            esb.securityBenchmarkStatus = rmd_pb2.SecurityBenchmarkStatus.Value(v)
            request.enterpriseSecurityBenchmarks.append(esb)
        api.communicate_rest(params, request, 'rmd/set_security_benchmarks', rs_type=None)
        print("Done")
