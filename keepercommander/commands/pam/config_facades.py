from typing import Optional, List, Dict, Any

from ... import vault, record_facades, record_types


class PamConfigurationRecordFacade(record_facades.TypedRecordFacade):
    _controller_uid_getter = record_facades.string_element_getter('_pam_resources', 'controllerUid')
    _controller_uid_setter = record_facades.string_element_setter('_pam_resources', 'controllerUid')
    _folder_uid_getter = record_facades.string_element_getter('_pam_resources', 'folderUid')
    _folder_uid_setter = record_facades.string_element_setter('_pam_resources', 'folderUid')
    _resource_ref_getter = record_facades.list_element_getter('_pam_resources', 'resourceRef')
    _file_ref_getter = record_facades.string_list_getter('_file_ref')

    def __init__(self):
        super(PamConfigurationRecordFacade, self).__init__()
        self._pam_resources = None    # type: Optional[vault.TypedField]
        self._port_mapping = None     # type: Optional[vault.TypedField]
        self._file_ref = None         # type: Optional[vault.TypedField]
        self._integrations = None     # type: Optional[vault.TypedField]

    def load_typed_fields(self):
        if self.record:
            self._pam_resources = next((x for x in self.record.fields if x.type == 'pamResources'), None)
            if not self._pam_resources:
                self._pam_resources = vault.TypedField.new_field('pamResources', [])
                self.record.fields.append(self._pam_resources)

            if len(self._pam_resources.value) > 0:
                if not isinstance(self._pam_resources.value[0], dict):
                    self._pam_resources.value.clear()

            if len(self._pam_resources.value) == 0:
                if 'pamResources' in record_types.FieldTypes and isinstance(record_types.FieldTypes['pamResources'].value, dict):
                    value = record_types.FieldTypes['pamResources'].value.copy()
                else:
                    value = {}
                self._pam_resources.value.append(value)

            self._port_mapping = next((x for x in self.record.fields
                                       if x.type == 'multiline' and x.label == 'portMapping'), None)
            if self._port_mapping is None:
                self._port_mapping = vault.TypedField.new_field('multiline', [], field_label='portMapping')
                self.record.fields.append(self._port_mapping)

            self._file_ref = next((x for x in self.record.fields if x.type == 'fileRef' and x.label == 'rotationScripts'), None)
            if self._file_ref is None:
                self._file_ref = vault.TypedField.new_field('fileRef', [], field_label='rotationScripts')
                self.record.fields.append(self._file_ref)

            # Load integrations field for CNAPP webhooks
            self._integrations = next((x for x in self.record.custom if x.type == 'json' and x.label == 'integrations'), None)
            if self._integrations is None:
                self._integrations = vault.TypedField.new_field('json', [], field_label='integrations')
                self.record.custom.append(self._integrations)

            if len(self._integrations.value) == 0:
                self._integrations.value.append({'cnapp': []})
            elif len(self._integrations.value) > 0:
                if not isinstance(self._integrations.value[0], dict):
                    self._integrations.value.clear()
                    self._integrations.value.append({'cnapp': []})
                elif 'cnapp' not in self._integrations.value[0]:
                    self._integrations.value[0]['cnapp'] = []
        else:
            self._pam_resources = None
            self._port_mapping = None
            self._file_ref = None
            self._integrations = None

        super(PamConfigurationRecordFacade, self).load_typed_fields()

    @property
    def controller_uid(self):
        return PamConfigurationRecordFacade._controller_uid_getter(self)

    @controller_uid.setter
    def controller_uid(self, value):
        PamConfigurationRecordFacade._controller_uid_setter(self, value)

    @property
    def folder_uid(self):
        return PamConfigurationRecordFacade._folder_uid_getter(self)

    @folder_uid.setter
    def folder_uid(self, value):
        PamConfigurationRecordFacade._folder_uid_setter(self, value)

    @property
    def resource_ref(self):
        return PamConfigurationRecordFacade._resource_ref_getter(self)

    @property
    def rotation_scripts(self):
        return PamConfigurationRecordFacade._file_ref_getter(self)

    # ==================== Integrations Field (CNAPP Webhooks) ====================

    @property
    def integrations(self) -> Dict[str, Any]:
        """Get the integrations field value."""
        if self._integrations and len(self._integrations.value) > 0:
            return self._integrations.value[0]
        return {'cnapp': []}

    @integrations.setter
    def integrations(self, value: Dict[str, Any]):
        """Set the integrations field value."""
        if self._integrations:
            if len(self._integrations.value) == 0:
                self._integrations.value.append(value)
            else:
                self._integrations.value[0] = value

    @property
    def cnapp_webhooks(self) -> List[Dict[str, Any]]:
        """Get the list of CNAPP webhooks from integrations.cnapp."""
        integrations = self.integrations
        return integrations.get('cnapp', [])

    @cnapp_webhooks.setter
    def cnapp_webhooks(self, webhooks: List[Dict[str, Any]]):
        """Set the list of CNAPP webhooks in integrations.cnapp."""
        integrations = self.integrations
        integrations['cnapp'] = webhooks
        self.integrations = integrations

    def add_cnapp_webhook(self, webhook: Dict[str, Any]) -> None:
        """Add a CNAPP webhook to the integrations.cnapp array."""
        webhooks = list(self.cnapp_webhooks)
        webhooks.append(webhook)
        self.cnapp_webhooks = webhooks

    def remove_cnapp_webhook(self, webhook_id: str) -> bool:
        """Remove a CNAPP webhook by ID. Returns True if found and removed."""
        webhooks = self.cnapp_webhooks
        original_count = len(webhooks)
        updated_webhooks = [w for w in webhooks if w.get('webhook_id') != webhook_id]
        if len(updated_webhooks) < original_count:
            self.cnapp_webhooks = updated_webhooks
            return True
        return False

    def get_cnapp_webhook(self, webhook_id: str) -> Optional[Dict[str, Any]]:
        """Get a specific CNAPP webhook by ID."""
        for webhook in self.cnapp_webhooks:
            if webhook.get('webhook_id') == webhook_id:
                return webhook
        return None

    def update_cnapp_webhook(self, webhook_id: str, updates: Dict[str, Any]) -> bool:
        """Update a CNAPP webhook by ID. Returns True if found and updated."""
        webhooks = self.cnapp_webhooks
        for i, webhook in enumerate(webhooks):
            if webhook.get('webhook_id') == webhook_id:
                webhooks[i] = {**webhook, **updates}
                self.cnapp_webhooks = webhooks
                return True
        return False
