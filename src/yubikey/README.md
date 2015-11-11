Yubikey Challenge-Response Module
----

This module uses the Yubikey Challenge-Response functionality to retrieve the Keeper Master Password

### Dependencies 

1) Install the below modules

```
pip3 install python-yubico
```

If you use Windows, you will require a PyUSB backend. Follow [this link](https://developers.yubico.com/python-yubico/)
for more information

2) Add your challenge to your config file

Here's an example config.json file:

```
{                                                                               
    "server":"https://keeperapp.com/v2/",
    "email":"your_email_here",
    "challenge":"your_challenge_here",
    "debug":false,
    "commands":[]
}
```

NOTE: The module assumes the Yubikey has been configured with HMAC-SHA1 Challenge-Response in Slot 2 and
your Keeper Master Password has been set as the response to your challenge
