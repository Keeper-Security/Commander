#!/usr/bin/env python3
"""
Connects to KCM Database (local/remote) and exports connections and connection groups.
Generates JSON file ready to be imported by pam project extend command.

Can handle the import of Connection Groups in three ways:
1 - Keeps the Connection Group nesting, except if the Group has a KSM configuration set, in which case it will mapped as a root gateway shared folder.
  ROOT/                                                                                                                                                                      
    └ Connection group A (no config)/                                                                                                                                        
       └ Connection group A1 (no config)/                                                                                                                                    
  Connection group B (config)/                                                                                                                                               
    └ Connection group B1 (no config)/    
    
2 - Keeps the exact Connection Group nesting                                                                                                                                                 
  ROOT/                                                                                                                                                                      
    ├ Connection group A/                                                                                                                                                    
    │   └ Connection group A1/                                                                                                                                               
    └ Connection group B/                                                                                                                                                    
        └ Connection group B1/   
        
3 - Maps all Connection Groups as root gateway shared folder                                                                                                                                                                  
  ROOT/                                                                                                                                                                      
  Connection group A/                                                                                                                                                        
  Connection group A1/                                                                                                                                                       
  Connection group B/                                                                                                                                                        
  Connection group B1/
"""

from json import dump,dumps,loads

## RICH Console styling - can be removed if rich was not imported ##
from rich.console import Console
from rich.markdown import Markdown
## RICH Console styling ##

DEBUG = False

HOSTNAME = '127.0.0.1'

DB_CONFIG = {
    'host': HOSTNAME,
    'user': 'guacamole_user',
    'password': 'password',
    'database': 'guacamole_db',
    'port': 3306
}

TOTP_ACCOUNT = 'kcm-totp%40keepersecurity.com'

SQL = {
    'groups': """
SELECT 
    cg.connection_group_id, 
    parent_id, 
    connection_group_name,
    cga.attribute_value AS ksm_config
FROM 
    guacamole_connection_group cg
LEFT JOIN 
    guacamole_connection_group_attribute cga
ON 
    cg.connection_group_id = cga.connection_group_id
    AND cga.attribute_name = 'ksm-config'
""",
    'connections': """
SELECT
    c.connection_id,
    c.connection_name AS name,
    c.protocol,
    cp.parameter_name,
    cp.parameter_value,
    e.name AS entity_name,
    e.type AS entity_type,
    g.connection_group_id,
    g.parent_id,
    g.connection_group_name AS group_name,
    ca.attribute_name,
    ca.attribute_value
FROM
    guacamole_connection c
LEFT JOIN
    guacamole_connection_parameter cp ON c.connection_id = cp.connection_id
LEFT JOIN
    guacamole_connection_attribute ca ON c.connection_id = ca.connection_id
LEFT JOIN
    guacamole_connection_group g ON c.parent_id = g.connection_group_id
LEFT JOIN
    guacamole_connection_permission p ON c.connection_id = p.connection_id
LEFT JOIN
    guacamole_entity e ON p.entity_id = e.entity_id;
"""
}

# Utils and CLI
USE_RICH = False

try:
    console = Console()
    USE_RICH = True
except:
    pass

def display(text,style=None):
    if USE_RICH:
        console.print(Markdown(text),style=style)
    else:
        print(text)
        
        
def list_items(items,style='italic yellow'):
    for item in items:
        display(f'- {item}',style)                                                                                                                                                                                                   
        
        
def handle_prompt(valid_inputs,prompt='Input: '):                                                                                                                                                                                    
    response = input(prompt)
    if response.lower() in valid_inputs:
        return valid_inputs[response]
    display('Invalid input')
    return handle_prompt(valid_inputs,prompt=prompt) 

                                                                                                                                                                                                                                     
def validate_file_upload(format,filename=None):                                                                                                                                                                                      
    if not filename:
        filename = input('File path: ')
    try:
        with open(filename,'r') as file:
            if format=='csv':
                from csv import DictReader
                return list(DictReader(file))
            elif format=='json':
                from json import load
                return load(file)
            elif format=='yaml':
                from yaml import safe_load
                return safe_load(file)
                
    except Exception as e:
        display(f'Error: Exception {e} raised','bold red')
        return validate_file_upload(format)


def debug(text,DEBUG):
    if DEBUG:
        print(f'>>DEBUG: {text}')


class KCM_export:
    def __init__(self,DEBUG=DEBUG):
        self.mappings = validate_file_upload('json','KCM_mappings.json')
        self.debug = DEBUG
        self.db_config = DB_CONFIG
        self.folder_structure = 'ksm_based'
        self.separator = '/'
        self.dynamic_tokens = []
        self.logged_records = {}
        
        display('# KCM Import','bold yellow')
        # Collect import method
        display('What database are you running on KCM?', 'cyan')
        list_items(['(1) MySQL','(2) PostgreSQL'])
        self.database = handle_prompt({'1':'MYSQL','2':'POSTGRES'})
        
        # Collect db credentials
        self.collect_db_config()
        
        # Connect to db
        connect = self.connect_to_db()
        if not connect:
            display('Unable to connect to database, ending program','bold red')
            return
        
        # Generate template
        json_template = self.generate_data()
              
        display('# Data collected and import-ready', 'green')
        display('Exporting JSON template...')
        with open('pam_import.json','w') as user_file:
            dump(json_template,user_file,indent=2)
        display('Exported pam_import.json successfully','italic green')
        
        return
        

    def collect_db_config(self):
        display('How do you wish to provide your database details?', 'cyan')
        list_items([
            '(1) By docker-compose.yml file',
            '(2) I have hardcoded them in the Python script'
        ])
        if handle_prompt({'1':'file','2':'code'}) == 'file':
            display('## Please upload your docker-compose file', 'cyan')
            self.docker_compose = validate_file_upload('yaml')
            
            port={'MYSQL':3306,'POSTGRES':5432}
            custom_port = None
            
            debug('Analysing services',self.debug)
            guacamole_env = self.docker_compose['services']['guacamole']['environment']
            db_in_compose = True
            host = "127.0.0.1"
            if guacamole_env.get(f'{self.database}_HOSTNAME','db') != 'db':
                debug('Alternate DB hostname detected',self.debug)
                host = guacamole_env[f'{self.database}_HOSTNAME']
                db_in_compose=False
            if db_in_compose and 'ports' in guacamole_env:
                custom_port = int(self.docker_compose["services"][guacamole_env[f"{self.database}_HOSTNAME"]]["ports"][0].split(':')[0])
            try:
                self.db_config = {
                    'host': host,
                    'user': guacamole_env[f'{self.database}_USERNAME'],
                    'password': guacamole_env[f'{self.database}_PASSWORD'],
                    'database': guacamole_env[f'{self.database}_DATABASE'],
                    'port': custom_port or port[self.database]
                }
            except:
                display('Unable to parse environment variables into suitable DB details. Please check that your docker-compose file has all relevant Guacamole variables, or hardcode them in the script','italic red')
                self.collect_db_config()
 
    
    def connect_to_db(self):
        if self.database == 'MYSQL':                                                                                                                                                                                                 
            try:                                                                                                                                                                                                                     
                from mysql.connector import connect
                debug('Attempting connection to database',self.debug)                                                                                                                                                                
                conn = connect(**self.db_config)
                cursor = conn.cursor(dictionary=True)                                                                                                                                                                                
                
                display('Database connection successful. Extracting data...','italic green')                                                                                                                                         
                
                debug('Extracting connection group data',self.debug)                                                                                                                                                                 
                cursor.execute(SQL['groups'])
                self.group_data = cursor.fetchall()                                                                                                                                                                                  
                
                debug('Extracting connection data',self.debug)                                                                                                                                                                       
                cursor.execute(SQL['connections'])
                self.connection_data = cursor.fetchall()
                
                display('Done','italic green')                                                                                                                                                                                       
                
                return True
                                                                                                                                                                                                                                     
            except mysql.connector.Error as e:                                                                                                                                                                                       
                display(f'MYSQL connector error: {e}','bold red')                                                                                                                                                                    
                return False
                                                                                                                                                                                                                                     
        elif self.database == 'POSTGRES':                                                                                                                                                                                            
            try:                                                                                                                                                                                                                     
                from psycopg2 import connect, OperationalError                                                                                                                                                                                      
                from psycopg2.extras import RealDictCursor                                                                                                                                                                           
                debug('Attempting connection to database',self.debug)                                                                                                                                                                
                conn = connect(**self.db_config)
                cursor = conn.cursor(cursor_factory=RealDictCursor)                                                                                                                                                                  
                                                                                                                                                                                                                                     
                display('Database connection successful. Extracting data...','italic green')                                                                                                                                         
                                                                                                                                                                                                                                     
                debug('Extracting connection group data',self.debug)                                                                                                                                                                 
                cursor.execute(SQL['groups'])                                                                                                                                                                                        
                group_rows = cursor.fetchall()
                self.group_data = [dict(row) for row in group_rows]                                                                                                                                                                  
                                                                                                                                                                                                                                     
                debug('Extracting connection data',self.debug)                                                                                                                                                                       
                cursor.execute(SQL['connections'])                                                                                                                                                                                   
                connection_rows = cursor.fetchall()                                                                                                                                                                                  
                self.connection_data = [dict(row) for row in connection_rows]                                                                                                                                                        
                
                display('Done','italic green')
                
                return True
            except OperationalError as e:    
                display(f'POSTGRESQL connector error: {e}','bold red')
                return False

    def generate_data(self):
        display('By default, this import will keep the Connection Group nesting you have set in KCM, but any Group with a KSM config will be modelled as a root shared folder', 'yellow')
        display('What handling do you want to apply to Connection Groups?','cyan')
        display('(1) Set Groups with KSM Config as Root Shared Folders (recommended)')
        display('''The folder structure will largely follow that of KCM, however any Connection Group with a KSM Service Configuration will be created as a root shared folder:  
ROOT/  
. └ Connection group A (no config)/  
.    └ Connection group A1 (no config)/  
Connection group B (config)/  
. └ Connection group B1 (no config)/  
        ''', 'yellow')
        display('(2) Keep exact KCM nesting')
        display('''The folder structure will replicate the exact same structure as KCM's:  
ROOT/  
. ├ Connection group A/  
. │   └ Connection group A1/  
. └ Connection group B/  
.     └ Connection group B1/  
        ''', 'yellow')
        display('(3) Flat')
        display('''All connection groups will be created as root shared folders:  
ROOT/  
Connection group A/  
Connection group A1/  
Connection group B/  
Connection group B1/  
        ''', 'yellow')
        self.folder_structure = handle_prompt({'1':'ksm_based','2':'nested','3':'flat'})
        
        self.group_paths = {}
    
        def resolve_path(group_id):
            if group_id is None:
                return "ROOT"
            if group_id in self.group_paths:
                return self.group_paths[group_id]
            # Find the group details
            group = next(g for g in self.group_data if g['connection_group_id'] == group_id)
            if self.folder_structure == 'ksm_based' and group['ksm_config']:
                self.group_paths[group_id] = group['connection_group_name']
                return group['connection_group_name']
            parent_path = resolve_path(group['parent_id'])
            full_path = f"{parent_path}{self.separator}{group['connection_group_name']}"
            self.group_paths[group_id] = full_path
            return full_path

        # Resolve paths for all groups
        for group in self.group_data:
            if self.folder_structure=='flat':
                self.group_paths[group['connection_group_id']] = group['connection_group_name']
            else:
                resolve_path(group['connection_group_id'])
        
        self.connections = {}
        self.users = {}
        self.shared_folders = []
        print(self.group_paths)
        
        for connection in self.connection_data:
            id = connection['connection_id']
            name = connection["name"]
            debug(f'Importing Connection {name}',self.debug)
            
            # Resolving folder path
            KCM_folder_path = self.group_paths.get(connection['connection_group_id'],'ROOT')
            folder_array = KCM_folder_path.split(self.separator)
            # Log Shared folder
            if folder_array[0] not in self.shared_folders:
                self.shared_folders.append(folder_array[0])
            
            # Add users
            if id not in self.users:
                # Create bespoke user folders
                folder_path = f'KCM Users - {folder_array[0]}'
                if len(folder_array)>1:
                    folder_path += self.separator+self.separator.join(folder_array[1:])
                # Create user
                user = {
                    'folder_path': folder_path,
                    'title': f'KCM User - {name}',
                    'type': "pamUser",
                    'rotation_settings':{}
                }
                self.users[id] = user
            
            # Add resources
            if id not in self.connections:
                # Create bespoke resource folders
                folder_path = f'KCM Resources - {folder_array[0]}'
                if len(folder_array)>1:
                    folder_path += self.separator+self.separator.join(folder_array[1:])
                    
                # Define record-type
                types = {
                    'http': 'pamRemoteBrowser',
                    'mysql': 'pamDatabase',
                    'postgres': 'pamDatabase',
                    'sql-server': 'pamDatabase',
                }
                    
                resource = {
                    'folder_path':folder_path,
                    'title': f'Resource {name}',
                    'type':types.get(connection['protocol'],'pamMachine'),
                    "host": "",
                    "pam_settings": {
                      "options": {
                        "rotation": "off",
                        "connections": "on",
                        "tunneling": "off",
                        "graphical_session_recording": "off"
                      },
                      "connection": {
                        "protocol": connection['protocol'] if connection['protocol'] != "postgres" else "postgresql",
                        "launch_credentials": f'KCM User - {name}'
                      }
                    }
                }                
                self.connections[id] = resource
            
            def handle_arg(id,name,arg,value):
                def handle_mapping(mapping,value,dir):
                    if mapping == 'ignore':
                        debug(f'Mapping {arg} ignored',self.debug)
                        return dir
                    if mapping=='log':
                        if name not in self.logged_records:
                            debug(f'Adding record {name} to logged records',self.debug)
                            self.logged_records[name] = {'name':name, arg:value}
                        else:
                            self.logged_records[name][arg] = value
                        return dir
                    if mapping is None:
                        debug(f'Mapping {arg} recognized but not supported',self.debug)
                        return dir
                    if '=' in mapping:
                        value = mapping.split('=')[1]
                        mapping = mapping.split('=')[0] 
                    if '.' in mapping:
                        param_array = mapping.split('.')
                        if len(param_array)>=2:
                            if param_array[0] not in dir[id]:
                                dir[id][param_array[0]] = {}
                            if len(param_array)==2:
                                dir[id][param_array[0]][param_array[1]] = value
                        if len(param_array)>=3:
                            if param_array[1] not in dir[id][param_array[0]]:
                                dir[id][param_array[0]][param_array[1]] = {}
                            if len(param_array)==3:
                                dir[id][param_array[0]][param_array[1]][param_array[2]] = value
                        if len(param_array)>=4:
                            if param_array[2] not in dir[id][param_array[0]][param_array[1]]:
                                dir[id][param_array[0]][param_array[1]][param_array[2]] = {}
                            dir[id][param_array[0]][param_array[1]][param_array[2]][param_array[3]] = value
                    else:
                        dir[id][mapping] = value
                    return dir
                
                if value.startswith('${KEEPER_') and id not in self.dynamic_tokens:
                    debug('Dynamic token detected',self.debug)
                    self.dynamic_tokens.append(id)
                    if name not in self.logged_records:
                        self.logged_records[name] = {'name':name, 'dynamic_token':True}
                    else:
                        self.logged_records[name]['dynamic_token'] = True
                elif value and arg.startswith('totp-'):
                    if 'oneTimeCode' not in user:
                        user['oneTimeCode'] = {
                            "totp-algorithm": '',
                            "totp-digits": "",
                            "totp-period": "",
                            "totp-secret": ""
                            }
                    user['oneTimeCode'][arg] = value
                elif value and arg == 'hostname':
                    resource['host'] = value
                elif value and arg == 'port':
                    resource['pam_settings']['connection']['port'] = value
                elif value and arg in self.mappings['users']:
                    self.users = handle_mapping(self.mappings['users'][arg],value,self.users)
                elif arg in self.mappings['resources']:
                    self.connections = handle_mapping(self.mappings['resources'][arg],value,self.connections)
                else:
                    display(f'Error: Unknown parameter detected: {arg}. Add it to KCM_mappings.json to resolve this error','bold red')
 
            # Handle args
            if connection['parameter_name']:
                handle_arg(id,connection['name'],connection['parameter_name'],connection['parameter_value'])
            # Handle attributes
            if connection['attribute_name']:
                handle_arg(id,connection['name'],connection['attribute_name'],connection['attribute_value'])

        
        self.user_records = list(user for user in self.users.values())
        self.resource_records = list(conn for conn in self.connections.values())
        
        # Sanitize totp
        for user in self.user_records:
            if 'oneTimeCode' in user:
                alg = user['oneTimeCode']["totp-algorithm"]
                dig = user['oneTimeCode']["totp-digits"]
                period = user['oneTimeCode']["totp-period"]
                secret = user['oneTimeCode']["totp-secret"]
                stripped_secret = ''.join([x for x in secret if x.isnumeric()])
                user['otp'] = f'otpauth://totp/{TOTP_ACCOUNT}?secret={stripped_secret}&issuer=&algorithm={alg}&digits={dig}&period={period}'
        
        # Handle SFTP records
        for resource in self.resource_records:
            if 'sftp' in resource['pam_settings']['connection']:
                sftp_settings = resource['pam_settings']['connection']['sftp']
                # Create resource for SFTP
                sftp_resource = {
                    'folder_path':resource['folder_path']+'/SFTP Resources',
                    'title': f'SFTP connection for resource {resource['host']}',
                    'type':'pamMachine',
                    "host": sftp_settings.get("host",""),
                    "port": sftp_settings.get("port",""),
                    "pam_settings": {
                      "options": {
                        "rotation": "off",
                        "connections": "off",
                        "tunneling": "off",
                        "graphical_session_recording": "off"
                      },
                      "connection": {
                        "protocol": 'ssh',
                        "launch_credentials": f'KCM User - {name}'
                      }
                    }
                }   
                self.resource_records.append(sftp_resource)
                # Create User for SFTP
                sftp_user = {
                    'folder_path':f'KCM Users - {resource["folder_path"][16:]}/SFTP Users',
                    'title': f'SFTP credentials for resource {resource['host']}',
                    'type':'pamUsers',
                    'login': sftp_settings.get("login",""),
                    'password': sftp_settings.get("password",""),
                    'private_pem_key': sftp_settings.get("private_key","")
                }
                self.user_records.append(sftp_user)
                # Set correct SFTP settings
                resource['pam_settings']['connection']['sftp'].update({
                    "sftp_resource": f'SFTP connection for resource {resource['host']}',
                    "sftp_user_credentials": f'SFTP credentials for resource {resource['host']}'
                })
                
        if self.dynamic_tokens:
            display(f'{len(self.dynamic_tokens)} dynamic tokens detected, they will be added to the JSON file.')
        if self.logged_records:
            display(f'{len(self.logged_records)-len(self.dynamic_tokens)} records logged, they will be added to the JSON file.')
        
        logged_records = []
        if self.logged_records:
            logged_records = (list(record for record in self.logged_records.values()))
        
        shared_folders = []
        for folder in self.shared_folders:
            shared_folders.extend([f'KCM Users - {folder}',f'KCM Resources - {folder}'])
        display('Make sure to add the following Shared Folders to your Gateway Application before importing:')
        list_items(shared_folders)
        
        return {
            "pam_data": {
                "shared_folders": shared_folders,
                "logged_records": logged_records,
                "resources": self.resource_records,
                "users": [user for user in self.user_records if len(user)>4]
            }
        }


KCM_export()
