# Debug IDE problem:
 - ```KeyError: 'PTVSD_SESSION_ID'```
  -> countermeasure: use embedding ```import pdb;pdb.set_trace()``` in python code file.
# Python pluginned debugger
 - launch.json
```json
{
    // Use IntelliSense to learn about possible attributes.
    // Hover to view descriptions of existing attributes.
    "version": "0.2.0",
    "configurations": [
        {
            "name": "Python: Keeper main",
            "type": "python",
            "request": "launch",
                        "stopOnEntry": true,
            "program": "${workspaceFolder}/keeper.py",
            "python.pythonPath": "${workspaceFolder}/env/bin/python",
            "args":[
                "--user user-email-address",
            "shell"
            ],
            "console": "integratedTerminal"
            
        }
    ]
}
``` 