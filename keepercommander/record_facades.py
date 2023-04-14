#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper SDK
# Copyright 2022 Keeper Security Inc.
# Contact: ops@keepersecurity.com
#

from typing import Optional, List, Callable, Any

from .vault import TypedRecord, TypedField


class TypedRecordFacade:
    def __init__(self):   # type: () -> None
        self._record = None     # type: Optional[TypedRecord]

    def _get_record(self):
        return self._record

    def _set_record(self, record):
        if record is None or isinstance(record, TypedRecord):
            self._record = record
            self.load_typed_fields()
        else:
            raise ValueError('expected TypedRecord')

    def _get_title(self):
        if isinstance(self._record, TypedRecord):
            return self._record.title
        raise ValueError('typed record is not assigned')

    def _set_title(self, value):
        if isinstance(self._record, TypedRecord):
            self._record.title = value
        else:
            raise ValueError('typed record is not assigned')

    def _get_notes(self):
        if isinstance(self._record, TypedRecord):
            return self._record.notes
        raise ValueError('typed record is not assigned')

    def _set_notes(self, value):
        if isinstance(self._record, TypedRecord):
            self._record.notes = value
        else:
            raise ValueError('typed record is not assigned')

    record = property(fget=_get_record, fset=_set_record)
    title = property(fget=_get_title, fset=_set_title)
    notes = property(fget=_get_notes, fset=_set_notes)

    def load_typed_fields(self):
        pass


def string_list_getter(name):   # type: (str) -> Callable[[TypedRecordFacade], List[str]]
    def getter(obj):
        field = getattr(obj, name)
        if isinstance(field, TypedField):
            return field.value
    return getter


def string_getter(name):   # type: (str) -> Callable[[TypedRecordFacade], str]
    def getter(obj):
        field = getattr(obj, name)
        if isinstance(field, TypedField):
            return field.value[0] if len(field.value) > 0 else ''
    return getter


def string_setter(name):   # type: (str) -> Callable[[Any, str], None]
    def setter(obj, value):
        field = getattr(obj, name)
        if isinstance(field, TypedField):
            if value:
                if len(field.value) > 0:
                    field.value[0] = value
                else:
                    field.value.append(value)
            else:
                field.value.clear()
    return setter


def string_element_getter(name, element_name):   # type: (str, str) -> Callable[[Any], str]
    def getter(obj):
        field = getattr(obj, name)
        if isinstance(field, TypedField):
            if len(field.value) > 0 and isinstance(field.value[0], dict):
                return field.value[0].get(element_name) or ''
    return getter


def string_element_setter(name, element_name):   # type: (str, str) -> Callable[[Any, str], None]
    def setter(obj, value):
        field = getattr(obj, name)
        if isinstance(field, TypedField):
            if value:
                if len(field.value) == 0:
                    field.value.append({})
                if isinstance(field.value[0], dict):
                    field.value[0][element_name] = value
            else:
                if len(field.value) > 0 and isinstance(field.value[0], dict):
                    field.value[0][element_name] = value
    return setter


def list_element_getter(name, element_name):   # type: (str, str) -> Callable[[TypedRecordFacade], list]
    def getter(obj):
        field = getattr(obj, name)
        if isinstance(field, TypedField):
            if len(field.value) > 0 and isinstance(field.value[0], dict):
                if element_name not in field.value[0] or not isinstance(field.value[0][element_name], list):
                    field.value[0][element_name] = []
                return field.value[0][element_name]
    return getter


class FileRefRecordFacade(TypedRecordFacade):
    _file_ref_getter = string_list_getter('_file_ref')

    def __init__(self):
        super(FileRefRecordFacade, self).__init__()
        self._file_ref = None       # type: Optional[TypedField]

    def load_typed_fields(self):
        if self.record:
            self._file_ref = next((x for x in self.record.fields if x.type == 'fileRef'), None)
            if self._file_ref is None:
                self._file_ref = TypedField.new_field('fileRef', [])
                self.record.fields.append(self._file_ref)
        else:
            self._file_ref = None
        super(FileRefRecordFacade, self).load_typed_fields()

    @property
    def file_ref(self):
        return FileRefRecordFacade._file_ref_getter(self)


class LoginRecordFacade(FileRefRecordFacade):
    _login_getter = string_getter('_login')
    _login_setter = string_setter('_login')
    _password_getter = string_getter('_password')
    _password_setter = string_setter('_password')
    _url_getter = string_getter('_url')
    _url_setter = string_setter('_url')
    _oneTimeCode_getter = string_getter('_oneTimeCode')
    _oneTimeCode_setter = string_setter('_oneTimeCode')

    def __init__(self):
        super(LoginRecordFacade, self).__init__()
        self._login = None        # type: Optional[TypedField]
        self._password = None     # type: Optional[TypedField]
        self._url = None          # type: Optional[TypedField]
        self._oneTimeCode = None  # type: Optional[TypedField]

    @property
    def login(self):
        return LoginRecordFacade._login_getter(self)

    @login.setter
    def login(self, value):
        LoginRecordFacade._login_setter(self, value)

    @property
    def password(self):
        return LoginRecordFacade._password_getter(self)

    @password.setter
    def password(self, value):
        LoginRecordFacade._password_setter(self, value)

    @property
    def url(self):
        return LoginRecordFacade._url_getter(self)

    @url.setter
    def url(self, value):
        LoginRecordFacade._url_setter(self, value)

    @property
    def oneTimeCode(self):
        return LoginRecordFacade._oneTimeCode_getter(self)

    @oneTimeCode.setter
    def oneTimeCode(self, value):
        LoginRecordFacade._oneTimeCode_setter(self, value)

    def load_typed_fields(self):
        if self.record:
            self.record.type_name = 'login'
            self._login = next((x for x in self.record.fields if x.type == 'login'), None)
            if self._login is None:
                self._login = TypedField.new_field('login', '')
                self.record.fields.append(self._login)
            self._password = next((x for x in self.record.fields if x.type == 'password'), None)
            if self._password is None:
                self._password = TypedField.new_field('password', '')
                self.record.fields.append(self._password)
            self._url = next((x for x in self.record.fields if x.type == 'url'), None)
            if self._url is None:
                self._url = TypedField.new_field('url', '')
                self.record.fields.append(self._url)
            self._oneTimeCode = next((x for x in self.record.fields if x.type == 'oneTimeCode'), None)
            if self._oneTimeCode is None:
                self._oneTimeCode = TypedField.new_field('oneTimeCode', '')
                self.record.fields.append(self._oneTimeCode)
        else:
            self._login = None
            self._password = None
            self._url = None
            self._oneTimeCode = None

        super(LoginRecordFacade, self).load_typed_fields()
