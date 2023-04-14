from typing import Optional

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
        else:
            self._pam_resources = None
            self._port_mapping = None
            self._file_ref = None

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
