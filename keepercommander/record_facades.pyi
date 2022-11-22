from typing import Optional, List

from .vault import TypedRecord

class TypedRecordFacade:
    record: Optional[TypedRecord]
    title: str
    notes: str
    def load_typed_fields(self) -> None: ...


class FileRefRecordFacade(TypedRecordFacade):
    @property
    def file_ref(self) -> List[str]: ...

class LoginRecordFacade(FileRefRecordFacade):
    login: str
    password: str
    url: str
    oneTimeCode: str
