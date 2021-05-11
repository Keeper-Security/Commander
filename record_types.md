### Record Types Commands

Record types use the same command syntax as legacy records but with minor modifications and a few additions all described below. Record types have following attributes: `type, title, notes, fields[] and custom[]`, the only required attributes are - `type` and any field marked as *required* in record type definition, but it is good idea to add at least a `title` to the record.

**Record Types Management Commands**

* ```add``` Add a record to the vault. Requires record type data as a JSON string, or loaded from file or as a command line options using dot notation (see examples below)

```add  --data '{"type":"login", "title":"MyLogin", "fields":[{"type": "login", "value": ["UserName"]}, {"type": "password", "value": ["Password"]}]}'```

```add  --data-file MyLogin.json```

```add  --option type=login -o title=MyLogin -o "notes=Record type notes"```

```add  -o type=login -o title=MyLoginToo -o fields.login=user -o fields.password=pass```

```add  -o type=contact -o title=MyContact -o f.name.first=John -o f.name.last=Doe```

```add  -o type=contact -o title=MyContact -o "note=Record type notes" -o "custom.notes=Very important note"```

Note: Dot notations using ```--option```  (or short version ```-o```) can handle only a single field per given type - if there are more fields of the same type (ex. in custom fields) please use JSON format for full record types capabilities.

* ```edit``` Edit a record in the vault. Requires record type data as a JSON string, or loaded from file or as a command line options using dot notation (see examples below)

```edit <UID> --data '{"type": "login", "title": "NewTitle", "notes": "Record type notes","fields": [{"type": "fileRef","value": []}]}'```

```edit <UID> -o title=NewTitleToo```

Note: To get the data as a JSON string for an existing record use ```get``` command with the following option ```--format=json``` For example to change just the title when using JSON format - just copy `data` JSON from ``get`` command then replace title only and use the modified JSON string in ```edit``` command, or use dot notation with ```--option``` to change only the title.
