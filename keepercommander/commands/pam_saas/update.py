from __future__ import annotations
import argparse
import logging
import traceback
from ..discover import PAMGatewayActionDiscoverCommandBase, GatewayContext
from ...display import bcolors
from ... import api, vault, vault_extensions, attachment, record_management, utils
from . import (get_plugins_map, make_script_signature, SaasCatalog, get_field_input, get_record_field_value,
               set_record_field_value)
from tempfile import TemporaryDirectory
import os
from typing import List, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from ...vault import TypedRecord
    from ...params import KeeperParams


class RecordNotConfigException(Exception):
    pass


class PAMActionSaasUpdateCommand(PAMGatewayActionDiscoverCommandBase):
    parser = argparse.ArgumentParser(prog='pam action saas update')

    parser.add_argument('--gateway', '-g', required=True, dest='gateway', action='store',
                        help='Gateway name of UID.')
    parser.add_argument('--all', '-a', required=False, dest='do_all', action='store_true',
                        help='Update all configurations.')
    parser.add_argument('--config-record-uid', '-c', required=False, dest='config_uid', action='store',
                        help='Update a specific configuration.')
    parser.add_argument('--dry-run', required=False, dest='do_dry_run', action='store_true',
                        help='Dry run. Do not save any changes.')

    def get_parser(self):
        return PAMActionSaasUpdateCommand.parser

    @staticmethod
    def get_field_values(record: TypedRecord, field_type: str) -> List[str]:
        return next(
            (f.value
             for f in record.fields
             if f.type == field_type),
            None
        )

    @classmethod
    def _get_file_refs(cls, record: TypedRecord) -> List[str]:
        return list(next((x.value for x in record.fields if x.type == "fileRef"), []))

    @classmethod
    def _update_script(cls, params: KeeperParams, config_record: TypedRecord, plugin: SaasCatalog):

        if plugin.type != "catalog":
            raise ValueError("Cannot download script for non-catalog plugin.")

        if not plugin.file:
            raise ValueError("Plugin does not have a file URL.")

        if not plugin.file_name:
            raise ValueError("Plugin does not have a file name.")

        print("  * downloading updated plugin script")
        res = utils.ssl_aware_get(plugin.file)
        if res.ok is False:
            raise ValueError("Could download updated script from GitHub")
        plugin_code_bytes = res.content

        new_script_sig = make_script_signature(plugin_code_bytes=plugin_code_bytes)

        if plugin.file_sig:
            logging.debug(f"downloaded {new_script_sig} vs catalog {plugin.file_sig}")
            if new_script_sig != plugin.file_sig:
                raise ValueError("The plugin signature in catalog does not match what was downloaded.")

        with TemporaryDirectory() as temp_dir:
            temp_file = os.path.join(temp_dir, plugin.file_name)
            with open(temp_file, "wb") as fh:
                fh.write(plugin_code_bytes)
                fh.close()

            task = attachment.FileUploadTask(temp_file)
            task.title = f"{plugin.name} Script"
            task.mime_type = "text/x-python"

            # Get the existing attached; we are going to remove these
            existing_file_refs = cls._get_file_refs(config_record)
            logging.debug(f"existing file ref: {existing_file_refs}")

            attachment.upload_attachments(params, config_record, [task])

            new_file_refs = cls._get_file_refs(config_record)
            logging.debug(f"new file ref: {new_file_refs}")

            if existing_file_refs is not None:
                logging.debug("existing file ref exists")
                for existing_file_ref in existing_file_refs:  # type: str
                    logging.debug(f"  * {existing_file_ref}")
                    if existing_file_ref in new_file_refs:
                        new_file_refs.remove(existing_file_ref)
            else:
                logging.debug("no existing file ref, use new file ref")

            logging.debug(f"save file ref: {new_file_refs}")

            config_record.fields = [
                vault.TypedField.new_field(
                    field_type="fileRef",
                    field_value=new_file_refs
                )
            ]

            record_management.update_record(params, config_record)
            params.sync_data = True

            print(f"  {bcolors.OKGREEN}* the plugin script is now up-to-date.{bcolors.ENDC}")

    @classmethod
    def _missing_fields(cls, config_record: TypedRecord, plugin: SaasCatalog) -> List[str]:

        # Make the record into a map by the field label
        records_field_map = {}
        for field in config_record.custom:
            records_field_map[field.label] = field

        missing_fields = []
        for field in plugin.fields:

            # We only care about required fields.
            if not field.required or field.default_value is not None:
                continue
            record_field = records_field_map.get(field.label)  # type: vault.TypedField
            if (record_field is None
                    or record_field.value is None
                    or len(record_field.value) == 0
                    or record_field.value[0] is None
                    or record_field.value[0] == ""):
                missing_fields.append(field.label)
        return missing_fields

    @classmethod
    def _update_config(cls,
                       params: KeeperParams,
                       plugins: dict[str, SaasCatalog],
                       config_record: TypedRecord,
                       dry_run: bool = False) -> Optional[SaasCatalog]:

        plugin_field = next((x for x in config_record.custom if x.label == "SaaS Type"), None)
        if plugin_field is None or len(plugin_field.value) == 0:
            logging.debug("record is not a SaaS Configuration record")
            raise RecordNotConfigException()
        plugin_name = plugin_field.value[0]
        logging.debug(f"plugin name is {plugin_name}")

        plugin = plugins.get(plugin_name)
        if plugin is not None and plugin.type == "catalog":

            missing_fields = cls._missing_fields(config_record=config_record, plugin=plugin)

            print(f"{bcolors.BOLD}{config_record.title} ({config_record.record_uid}) - {plugin_name}{bcolors.ENDC}")
            logging.debug(f"plugin is {plugin_name} for config {config_record.title}")
            attachments = list(attachment.prepare_attachment_download(params, config_record.record_uid))

            # If there is no script, just attach script to record.
            # Someone might have deleted the script from the record.
            if len(attachments) == 0:
                print("  * the record does not contain a plugin script.")
                logging.debug("  * configuration did not have script, add current script.")

                if not dry_run:
                    cls._update_script(
                        params=params,
                        config_record=config_record,
                        plugin=plugin,
                    )
                else:
                    print(f"  {bcolors.OKBLUE}* not updating script due to dry run.{bcolors.ENDC}")

                if len(missing_fields) == 0:
                    print(f"  {bcolors.OKGREEN}* the configuration record fields are up-to-date.{bcolors.ENDC}")
                else:
                    print(f"  {bcolors.FAIL}* the configuration record's required field(s) are missing or blank: "
                          f"{', '.join(missing_fields)}{bcolors.ENDC}")
                print("")
                return plugin

            logging.debug(f"found {len(attachments)} attached script(s).")

            if len(attachments) > 1:
                raise ValueError("Found multiple scripts. Only one script is allowed per SaaS Configuration record.")

            for atta in attachments:
                with TemporaryDirectory() as temp_dir:
                    if not plugin.file_name:
                        logging.debug("plugin does not have a file name, using default")
                        temp_file = str(os.path.join(temp_dir, f"{plugin.name}_script.py"))
                    else:
                        temp_file = str(os.path.join(temp_dir, plugin.file_name))
                    logging.debug(f"download to {temp_file}")

                    # download_to_file prints to the screen, we don't want that.
                    log_level = logging.getLogger().getEffectiveLevel()
                    try:
                        logging.getLogger().setLevel(logging.WARNING)
                        atta.download_to_file(params, temp_file)
                    finally:
                        logging.getLogger().setLevel(log_level)

                    with open(temp_file, "rb") as fh:
                        plugin_code_bytes = fh.read()
                        fh.close()

                    attach_file_sig = make_script_signature(plugin_code_bytes=plugin_code_bytes)
                
                if plugin.file_sig:
                    logging.debug(f"attached {attach_file_sig} vs catalog {plugin.file_sig}")
                    sig_matches = attach_file_sig == plugin.file_sig
                else:
                    logging.debug("plugin does not have a file signature, skipping verification")
                    sig_matches = True
                
                if not sig_matches:
                    print(f"  {bcolors.WARNING}* the plugin script have changed.{bcolors.ENDC}")
                    logging.debug("the script has changed, update")

                    if not dry_run:
                        cls._update_script(
                            params=params,
                            config_record=config_record,
                            plugin=plugin,
                        )
                    else:
                        print(f"  {bcolors.OKBLUE}* not updating script due to dry run.{bcolors.ENDC}")
                else:
                    print(f"  {bcolors.OKGREEN}* the plugin script is up-to-date.{bcolors.ENDC}")

                if len(missing_fields) == 0:
                    print(f"  {bcolors.OKGREEN}* the configuration record fields are up-to-date.{bcolors.ENDC}")
                else:
                    print(f"  {bcolors.FAIL}* the configuration record's required field(s) are missing or blank: "
                          f"{', '.join(missing_fields)}{bcolors.ENDC}")
                print("")
                return plugin

        logging.debug("plugin doesn't used attached scripts, or bad SaaS type in config record.")
        return None

    def execute(self, params: KeeperParams, **kwargs):

        gateway = kwargs.get("gateway")  # type: str
        do_all = kwargs.get("do_all", False)  # type: bool
        config_record_uid = kwargs.get("config_uid")  # type: str
        do_dry_run = kwargs.get("do_dry_run", False)  # type: bool

        gateway_context = GatewayContext.from_gateway(params, gateway)
        if gateway_context is None:
            print("")
            print(f"{bcolors.FAIL}Could not find the gateway configuration for {gateway}.")
            return

        print("")

        if do_dry_run:
            print(f"{bcolors.WARNING}Dry run enabled. No changes will be saved.{bcolors.ENDC}")
            print("")

        plugins = get_plugins_map(
            params=params,
            gateway_context=gateway_context
        )


        if do_all:
            logging.debug("search vault for login record types")
            for record in list(vault_extensions.find_records(params, record_type="login")):
                logging.debug("--------------------------------------------------------------------------------------")
                config_record = vault.TypedRecord.load(params, record.record_uid)  # type: vault.TypedRecord
                logging.debug(f"checking record {record.record_uid}, {record.title}")
                try:
                    self._update_config(
                        params=params,
                        plugins=plugins,
                        config_record=config_record,
                        dry_run=do_dry_run
                    )
                except RecordNotConfigException:
                    pass
                except Exception as err:
                    print(f"  *{bcolors.FAIL}{err}{bcolors.ENDC}")
                    logging.debug(traceback.format_exc())
                    logging.debug(f"ERROR (no fatal): {err}")

        elif config_record_uid is not None:
            config_record = vault.TypedRecord.load(params, config_record_uid)  # type: vault.TypedRecord
            if config_record is None:
                print("")
                print(f"{bcolors.FAIL}Cannot find a record for UID {config_record_uid}.{bcolors.ENDC}")
                return

            try:
                plugin = self._update_config(
                    params=params,
                    plugins=plugins,
                    config_record=config_record,
                    dry_run=do_dry_run
                )
                if plugin is not None:
                    missing_fields = self._missing_fields(config_record=config_record, plugin=plugin)

                    if len(missing_fields) > 0:

                        # If we added a script, we need to sync down to get the record version number correct.
                        api.sync_down(params)
                        config_record = vault.TypedRecord.load(params, config_record_uid)  # type: vault.TypedRecord

                        for required in [True, False]:
                            for field in plugin.fields:
                                if field.required is required:
                                    current_value = get_record_field_value(
                                        record=config_record,
                                        label=field.label
                                    )
                                    print("")
                                    value = get_field_input(field, current_value=current_value)
                                    if value is not None:
                                        set_record_field_value(
                                            record=config_record,
                                            label=field.label,
                                            value=value
                                        )

                        if not do_dry_run:
                            record_management.update_record(params, config_record)
                            print("")
                            print(f"  {bcolors.OKGREEN}* the configuration record has been updated.{bcolors.ENDC}")
                            print("")
                        else:
                            print("")
                            print(f"  {bcolors.OKBLUE}* the configuration record was not saved due "
                                  f"to dry run.{bcolors.ENDC}")
                            print("")

                        params.sync_data = True

            except Exception as err:
                print("")
                logging.debug(traceback.format_exc())
                print(f"{bcolors.FAIL}{err}{bcolors.ENDC}.")
                return
        else:
            print("")
            print(f"{bcolors.FAIL}Requires either the --all or --config-record-uid parameters.{bcolors.ENDC}")
            print("")
            PAMActionSaasUpdateCommand.parser.print_help()
