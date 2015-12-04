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
    "user":"your_email_here",
    "challenge":"your_challenge_here",
    "debug":false,
    "commands":[]
}
```

NOTE: The module assumes the Yubikey has been configured with HMAC-SHA1 Challenge-Response in Slot 2 and
your Keeper Master Password has been set as the response to your challenge

Yubikey Configuration
---

### Launch the YubiKey Personalization Tool
<img src="images/screen1.png">

### Click the Challenge-Response Mode link
<img src="images/screen2.png">

### Select HMAC-SHA1
<img src="images/screen3.png">

### Choose Configuration Slot 2, click the Generate button and then the Write Configuration button
<img src="images/screen4.png">

### Click the Tools menu option, choose Configuration Slot 2, select HMAC-SHA1 and choose a unique challenge string

NOTE: Remember your unique challenge string as it will be needed for your config.json file
<img src="images/screen5.png">

### Push the Perform button
<img src="images/screen6.png">

### Copy the Response value and set your Vault's Master Password to that value
<img src="images/screen7.png">
