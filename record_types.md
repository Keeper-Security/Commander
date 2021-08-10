### Record Types Commands
_Currently available only to enterprise users._

Record types help to better organize and manage records in the vault. They use a new format for Keeper records supporting different record types - Record Format V3.

__Record types basics:__
 - **Record Types** - A set of default and custom combination of fields named based on their primary use (email, social media, SSH, etc.)
 - **Field Types** - Individual default fields that are assignable to record and record types. Fields such as "street #", "ZIP", "password", "TOTP code", "First Name", "Credit Card number" are available to all records. If a user wants to create a record type "Email", we will provide "default fields" such as "username", "password", "email domain", but the user can always add an additional field such as "address" if they choose to
  - **Categories** - A default combination of "Record Types"

Record types use the same command syntax as legacy records with minor modifications and a few additional commands to work with new records and fields. A new record V3 has following attributes: `type, title, notes, fields[] and custom[]`, the only required attributes are - `type` and any field (in `fields[]`) marked as `"required": true` in the record type definition, and adding a `title` to the record is always encouraged.

**Records V3 Management Commands**

* ```add``` Add a record to the vault. Requires record type data as a JSON string or loaded from file or provided as a command line options using dot notation (see examples below)

```add  --data '{"type":"login", "title":"MyLogin", "fields":[{"type": "login", "value": ["UserName"]}, {"type": "password", "value": ["Password"]}]}'```

```add  --from-file MyLogin.json```

```add  type=login title=MyLogin "notes=Record type notes"```

```add  type=login title=MyLoginToo fields.login=user fields.password=pass```

```add  type=contact title=MyContact f.name.first=John f.name.last=Doe```

```add  type=contact title=MyContact f.name.first=John f.name.last=Doe "notes=Record type notes" "custom.note=Very important note"```

Note: Dot notations can handle only a single field per given type - if there are more fields of the same type (ex. in custom[] section) please use JSON format for full record types capabilities.

* ```edit``` Edit a record in the vault. Requires record type data as a JSON string or loaded from file or provided as a command line options using dot notation (see examples below)

```edit -r <UID> --data '{"type": "login", "title": "NewTitle", "notes": "Record type notes","fields": [{"type": "fileRef","value": []}]}'```

```edit -r <UID> title=NewTitleToo```

```edit -r <UID> fields.login=NewLogin f.password=NewPassword```

```edit -r <UID> f.name.first=Jane f.name.last=Doe```

Note: To get the data as a JSON string for an existing record use ```get``` command with the following option ```--format=json``` For example to change just the title when using JSON format - just copy `data` JSON from ``get`` command then replace title only and use the modified JSON string in ```edit``` command, or use dot notation to change only the title.

**Record Types Management Commands**

To create, update and delete custom record types use `record-type` command:

```record-type --action add --data '{"$id": "newType", "categories": ["note"], "fields":[{"$ref": "note"}]}'```

```record-type --action update <RTID>  --data '{"$id": "newType", "categories": ["address"], "fields":[{"$ref": "note"},{"$ref": "address"}]}'```

```record-type --action remove <RTID>```

The `--data` parameter expects record type definition JSON in the same format as the one provided by `record-type-info` - ex. `rti -lr login`

To show available record types definitions use `record-type-info` command:

```
record-type-info --list-record
record-type-info --list-record 1
record-type-info --list-record login
rti -lr
rti -lr login
```

```
record-type-info --list-record --format=csv
rti -lr --format=json --output record_types.json
```

Note: Output file name is ignored for table format.

To show available field types definitions use `record-type-info --list-field *` command:

```
record-type-info --list-field *
record-type-info --list-field login
rti -lf name
rti -lf name --format=json
rti -lf phone --example
```
