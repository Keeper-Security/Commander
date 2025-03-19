![Keeper Commander](https://raw.githubusercontent.com/Keeper-Security/Commander/master/images/commander-black.png)

### About Keeper Commander
Keeper Commander is a command-line and SDK interface to Keeper® Password Manager. Commander can be used to access and control your Keeper vault, perform administrative functions (such as end-user onboarding and data import/export), launch remote sessions, rotate passwords, eliminate hardcoded passwords and more. Keeper Commander is an open source project with contributions from Keeper's engineering team and partners.

### Documentation 
To read the Keeper Commander documentation please click here:

[https://docs.keeper.io/secrets-manager/commander-cli/overview](https://docs.keeper.io/secrets-manager/commander-cli/overview)

### About Keeper Security
Keeper is the leading cybersecurity platform for preventing password-related data breaches and cyberthreats.

Learn More at:
[https://keepersecurity.com](https://keepersecurity.com)


## Docker Build (Commander Service Mode)
 Installation
  1. Install [Docker](https://www.docker.com/).
  2. Clone the repository [git clone](https://github.com/Keeper-Security/Commander.git).
  3. Build docker image using command  ``` docker build -t keeper-commander . ```
  4. Verify docker image created. ``` docker images ```
  5. Run the keeper-commander docker image using command
     ``` docker run -d -p <port>:<port> keeper-commander \```
      ```service-create -p <port> -c '<commands using comma seprated like tree,ls>' \```
      ```--user $KEEPER_USERNAME \```
      ```--password $KEEPER_PASSWORD ```
   6. Verify keeper-commander image is started using command ``` docker ps ```
   7. Check the logs using command ```docker logs <Process Name>``` and get the API key from logs
       ```Generated API key: <API-KEY>```

### Execute Command Endpoint

```bash
curl --location 'http://localhost:<port>/api/v1/executecommand' \
--header 'Content-Type: application/json' \
--header 'api-key: <your-api-key>' \
--data '{
    "command": "<command>"
}'
```
