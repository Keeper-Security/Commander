# Protoc

## Overview

The GraphSync_* can be copied from Commander.
router.proto is a shortened version without the dependencies.

## Get Protoc

https://github.com/protocolbuffers/protobuf/releases/tag/v3.19.4

1. Create a directory for the protoc. It will unzip to that directory.
2. Download the ZIP for your machine into that directory.
   * macOS - https://github.com/protocolbuffers/protobuf/releases/download/v3.19.4/protoc-3.19.4-osx-x86_64.zip
   * Windows - https://github.com/protocolbuffers/protobuf/releases/download/v3.19.4/protoc-3.19.4-win64.zip
3. Unzip.

## macOS

On macOS, you will need to approve the running of `protoc`.
This can be done by running `protoc`, approving the dialog box, then going
  to the **Privacy & Security** tab in the **Settings**. 
In the **Security** section, allow `protoc` to run. 
The next time you run `protoc`, you'll still  get a popup, but it will allow 
  the application to run.


## Proto Files

`GraphSync.proto` can be found at https://github.com/Keeper-Security/keeperapp-protobuf/blob/master/GraphSync.proto .

`router_abbr.proto` is an abbreviated version of `router.proto`. The real file is at https://github.com/Keeper-Security/keeperapp-protobuf/blob/master/router.proto, but
it included many dependencies which keeper-dag would never use.


## Compile the proto files

```shell
pip install protobuf mypy-protobuf
cd keeper-dag/proto
/path/to/protoc/bin/protoc --python_out=. --mypy_out=. router_abbr.proto
/path/to/protoc/bin/protoc --python_out=. --mypy_out=. router_abbr.proto
```



