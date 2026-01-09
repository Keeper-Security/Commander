''' _  __
   | |/ /___ ___ _ __  ___ _ _ ®
   | ' </ -_) -_) '_ \/ -_) '_|
   |_|\_\___\___| .__/\___|_|
                |_|

Keeper Commander
Description: 

  This script demonstrates how to automate the onboarding of user accounts in an enterprise, and connecting into each new vault via KeeperCommander for ultimate control over its content. 

  - If the email domain has not been reserved, the account creation will fail.

  - If a user already exists for the email:
     - and its status is invited, the account will be deleted and replaced with an active one (can be disabled with replace_invited param).
     - and its status is active, the account creation is skipped but the program will still attempt to login by looking for a Master Password record on the admin vault.
     
  - After actions are performed on the user vaults, their Master Password is expired again - which will prompt a new reset when the user logs in.

Usage:
  - For a quick test, replace the emails for User_A and User_B below with valid emails for your enterprise. 
    The script runs import actions will expect a 'json_file.json' and 'csv_file.csv' in the current directory.
  - For production, leverage the get_user_vault function to create and log into vaults, along with any KeeperCommander method to add content.
'''

USER_A = 'infra@disposable-domain.work.gd'
USER_B = 'devops@disposable-domain.work.gd'

from keepercommander.params import KeeperParams
from keepercommander import api
from keepercommander import cli
from keepercommander.loginv3 import LoginV3Flow
from keepercommander.commands.enterprise import EnterpriseUserCommand
eu = EnterpriseUserCommand()
login_v3_flow = LoginV3Flow()

def compile_users(params): # (KeeperParams) => list,list
    api.query_enterprise(params)
    active_usernames = [user['username'] for user in params.enterprise['users'] if user['status']!='invited']
    invited_users = [user for user in params.enterprise['users'] if user['status']=='invited']
            
    return active_usernames, invited_users


def generate_password(params,length=20): # (KeeperParams, int) => str
    from keepercommander.generator import generate
    import re
    password_rules, min_iterations = login_v3_flow.get_default_password_rules(params)
    while True:
        password = generate(length)

        failed_rules = []
        for rule in password_rules:
            pattern = re.compile(rule.pattern)
            if not re.match(pattern, password):
                failed_rules.append(rule.description)
        if len(failed_rules) == 0:
            return password


def get_user_vault(admin_params, user, folder=None, password_length=20, replace_invited=True): # (KeeperParams, dict, str, int, bool) => KeeperParams
    '''
    user_dict_format = {
        'username': 'user@email.com'
        'node_id': 1067368092533492,     # Optional, also supports name
        'full_name': 'Example Name',     # Optional
        'job_title': 'Example Job Title' # Optional
    }
    Folder must already exist in admin vault for folder flag
    ''' 
    
    from keepercommander.commands.enterprise_create_user import CreateEnterpriseUserCommand
    
    if not user['username']:
        print('get_user_vault function needs at least a username')
        return
    email = user['username']
    
    # Get all users by status
    active_usernames, invited_users = compile_users(admin_params)
         
    # Delete invited (if allowed)
    for invited_user in invited_users:
        if invited_user['username'] == email:
            print(f'Invited user for {email} found',end='')
            if not replace_invited:
                print(' - Not allowed to replace, could not create user.')
                return
            print(' - replacing...')
            eu.execute(admin_params,email=[email],delete=True,force=True)
            # replace empty user fields with that of found user
            for key in ['node_id','full_name','job_title']:
                if user.get(key,None) is None and invited_user.get(key,None) is not None:
                    user[key] = invited_user[key]
                
    # Create user
    user_record = None
    if email not in active_usernames:
        print(f'Creating user vault for {email}...')
        record_uid = CreateEnterpriseUserCommand().execute(admin_params,email=email,node=user.get('node_id',None),name=user.get('full_name',None),folder=folder)
        user_record = api.get_record(admin_params,record_uid)
        eu.execute(admin_params,email=[email],jobtitle=user.get('job_title',None))
    else:
        print(f'Active user found for {email}. Could not create user, but will attempt to sign in using vault records.')
        record_search = api.search_records(admin_params,f'Keeper Account: {email}')
        if len(record_search)!=1:
            print(f'Error looking up record with title "Keeper Account: {email}". Could not sign in as user.')
            return
        user_record = record_search[0]
               
    if user_record is None:
        print(f'Error looking up record with UID {record_uid}')
        return

    # Sign in as user
    print(f'Signing in as user {email}...')
    user_params = KeeperParams()
    user_params.user = email
    user_params.password = user_record.password
    
    if email not in active_usernames:
        # Reset tmp pwd
        new_password = generate_password(admin_params)
        login_v3_flow.login(user_params, new_password_if_reset_required=new_password)
        
        # Update record password
        user_params.password = new_password
        from keepercommander.commands.record_edit import RecordUpdateCommand
        RecordUpdateCommand().execute(admin_params, record=record_uid, fields=[f'password={new_password}'])

    api.login(user_params)
    api.sync_down(user_params)
    print('Sign in Successful')
    return user_params
    

# RUNTIME

# Login as admin
print('Signing in as admin...')
admin_params = KeeperParams()
admin_params.user = input('Admin email: ')
api.login(admin_params)
api.sync_down(admin_params)

# Create/get vault for User A (minimal example)
user_a_params = get_user_vault(admin_params,{'username':USER_A})
# Create/get vault for User B (extended example)
user_b_params = get_user_vault(
    admin_params,
    {
        'username':USER_B,
        'full_name': 'Jane Doe',
        'job_title': 'DevOps Engineer'
    },
    folder='DevOps users'
)

# Run ad-hoc commands for User A
cli.do_command(user_a_params,'mkdir "Sample user folder" -uf')
cli.do_command(user_a_params,'record-add -rt login -t "Sample record" --folder "Sample user folder"')

from keepercommander.importer.imp_exp import _import as run_import
# Run CSV import for User A
run_import(user_a_params, 'csv', 'csv_file.csv')

# Run JSON import for User B
run_import(user_b_params, 'json', 'json_file.json')

# Re-expire Master Passwords
eu.execute(admin_params, email=[USER_A,USER_B], expire=True, force=True)
