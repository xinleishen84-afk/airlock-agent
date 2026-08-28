from google.protobuf.internal import containers as _containers
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from collections.abc import Iterable as _Iterable, Mapping as _Mapping
from typing import ClassVar as _ClassVar, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class AnalyzeRequest(_message.Message):
    __slots__ = ("text", "language", "entity_types")
    TEXT_FIELD_NUMBER: _ClassVar[int]
    LANGUAGE_FIELD_NUMBER: _ClassVar[int]
    ENTITY_TYPES_FIELD_NUMBER: _ClassVar[int]
    text: str
    language: str
    entity_types: _containers.RepeatedScalarFieldContainer[str]
    def __init__(self, text: _Optional[str] = ..., language: _Optional[str] = ..., entity_types: _Optional[_Iterable[str]] = ...) -> None: ...

class NEREntity(_message.Message):
    __slots__ = ("entity_type", "start", "end", "text", "score")
    ENTITY_TYPE_FIELD_NUMBER: _ClassVar[int]
    START_FIELD_NUMBER: _ClassVar[int]
    END_FIELD_NUMBER: _ClassVar[int]
    TEXT_FIELD_NUMBER: _ClassVar[int]
    SCORE_FIELD_NUMBER: _ClassVar[int]
    entity_type: str
    start: int
    end: int
    text: str
    score: float
    def __init__(self, entity_type: _Optional[str] = ..., start: _Optional[int] = ..., end: _Optional[int] = ..., text: _Optional[str] = ..., score: _Optional[float] = ...) -> None: ...

class AnalyzeResponse(_message.Message):
    __slots__ = ("entities", "model", "inference_micros")
    ENTITIES_FIELD_NUMBER: _ClassVar[int]
    MODEL_FIELD_NUMBER: _ClassVar[int]
    INFERENCE_MICROS_FIELD_NUMBER: _ClassVar[int]
    entities: _containers.RepeatedCompositeFieldContainer[NEREntity]
    model: str
    inference_micros: int
    def __init__(self, entities: _Optional[_Iterable[_Union[NEREntity, _Mapping]]] = ..., model: _Optional[str] = ..., inference_micros: _Optional[int] = ...) -> None: ...

class HealthRequest(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class HealthResponse(_message.Message):
    __slots__ = ("ready", "model", "supported_types", "detail")
    READY_FIELD_NUMBER: _ClassVar[int]
    MODEL_FIELD_NUMBER: _ClassVar[int]
    SUPPORTED_TYPES_FIELD_NUMBER: _ClassVar[int]
    DETAIL_FIELD_NUMBER: _ClassVar[int]
    ready: bool
    model: str
    supported_types: _containers.RepeatedScalarFieldContainer[str]
    detail: str
    def __init__(self, ready: _Optional[bool] = ..., model: _Optional[str] = ..., supported_types: _Optional[_Iterable[str]] = ..., detail: _Optional[str] = ...) -> None: ...
