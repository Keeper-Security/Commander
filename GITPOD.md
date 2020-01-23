# How to in-menu Git
 ## View/SCM
    Modified files are marked 'M'
  - File name -> Difference view
  - Open file -> Window([->]) icon
  - Stage (add to commit-booking files) -> '+'
  - Message : for commit -m 


#Settings: /File
 ## Preferences(Python Version): 
   - Workspace: 
   ```json {
   "python.pythonPath": "venv/bin/python3.7",
   "editor.autoSave": "on"
    }
    ```
 - launch.json (in-menu debugger settings)
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

# Debug IDE problem:
 - ```KeyError: 'PTVSD_SESSION_ID'```
  -> countermeasure: use embedding ```import pdb;pdb.set_trace()``` in python code file.

