# TODO items: what I want to do ideas
 - Ignore accent characters when search :
```
   Use unocodedata.normalize('NFKD', s) and unicodedata.category(c) != 'Mn'
   ```
# Done
 - Fix logging : print modules and functions by setting a proper format 
```
    Specify the format by __logging_format__ string in keepercommander/__init__.py
    ```
 - Refuse inproper port number for web view