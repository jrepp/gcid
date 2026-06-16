"""Cryptographic, location aware ID conversions."""

import logging
from dataclasses import dataclass
from enum import Enum
from types import SimpleNamespace
from typing import Any

import base58
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCMSIV
from pydantic_core import core_schema

from gcid.config import Config

_config = Config()

# ID encoding constants
_GCID_VERSION = 2
_SUITE_AES_256_GCM_SIV = 1
_SCHEMA_SEQ64_LOC56 = 1
_DEFAULT_KEY_ID = 0

_HEADER_BYTES = 4
_TAG_BYTES = 16
_LOCATION_BYTES = 7
_SEQ_BYTES = 8
_PLAINTEXT_BYTES = _LOCATION_BYTES + _SEQ_BYTES
_PAYLOAD_BYTES = _HEADER_BYTES + _PLAINTEXT_BYTES + _TAG_BYTES

_ENC_KEY: bytes = _config.gcid_enc_key.encode('utf-8')
if len(_ENC_KEY) != 32:
    raise ValueError('gcid_enc_key must encode to exactly 32 bytes')

_NONCE = b'\00' * 12
_AAD_DOMAIN = b'GCIDv2'
_HEADER = bytes(
    (
        _GCID_VERSION,
        _SUITE_AES_256_GCM_SIV,
        _SCHEMA_SEQ64_LOC56,
        _DEFAULT_KEY_ID,
    )
)

_LOCATION_PARTITION = b'\00' * _LOCATION_BYTES
_aead = AESGCMSIV(_ENC_KEY)

log = logging.getLogger(__name__)


class IdType(Enum):
    """Type enum for ID prefixes"""

    PROFILE = 'prf'
    ORG = 'org'
    ASSET = 'asset'
    FILE = 'file'
    EVENT = 'evt'
    TOPO = 'topo'
    JOBDEF = 'jobdef'
    JOB = 'job'
    JOBRESULT = 'jobres'
    READER = 'read'
    TAG = 'tag'


class ApiError(Exception):
    def __init__(self, message):
        super().__init__(message)


class IdError(Exception):
    def __init__(self, id_str: str, reason: str):
        super().__init__(f'API ID {id_str} is not valid: {reason}')


class SequenceError(ApiError):
    def __init__(self, seq_num: int, reason: str):
        super().__init__(f'sequence number {seq_num} is not valid: {reason}')


id_rev_map = {i.value: i for i in list(IdType)}


@dataclass(frozen=True, slots=True)
class DbSeq:
    id_type: IdType | str
    prefix: bytes
    seq: int
    location: bytes = _LOCATION_PARTITION


def _id_prefix(api_id: str) -> str:
    """Return the string prefix from an API ID."""
    if not isinstance(api_id, str):
        raise IdError(api_id, f'invalid api id type {type(api_id)}')

    parts = api_id.split('_')
    if len(parts) != 2:
        raise IdError(api_id, f'invalid api id format {api_id}')

    return parts[0]


def _type_prefix(api_type: Any) -> str:
    if isinstance(api_type, IdType):
        return api_type.value

    if isinstance(api_type, str):
        return api_type

    if isinstance(api_type, type) and issubclass(api_type, Gcid):
        return api_type.prefix

    prefix = getattr(api_type, 'prefix', None)
    if isinstance(prefix, str):
        return prefix

    value = getattr(api_type, 'value', None)
    if isinstance(value, str):
        return value

    raise TypeError(f'invalid id type {api_type!r}')


def _location_bytes(location: bytes | int | None) -> bytes:
    if location is None:
        return _LOCATION_PARTITION

    if isinstance(location, int):
        if location < 0 or location >= 2**56:
            raise ValueError('location must fit in 56 bits')
        return location.to_bytes(7, 'big')

    if isinstance(location, bytes):
        if len(location) != _LOCATION_BYTES:
            raise ValueError('location must be exactly 7 bytes')
        return location

    raise TypeError(f'invalid location type {type(location)}')


def _type_location(api_type: Any) -> bytes:
    return _location_bytes(getattr(api_type, 'location', None))


def _api_id_prefix(location: bytes | int | None = None) -> bytes:
    return _HEADER + _location_bytes(location)


def _validate_wire_prefix(prefix: str) -> None:
    if not prefix or '_' in prefix:
        raise ValueError(
            f'id prefix must be non-empty and not contain _: {prefix!r}'
        )

    try:
        prefix.encode('ascii')
    except UnicodeEncodeError as exc:
        raise ValueError(f'id prefix must be ASCII: {prefix!r}') from exc


def _aad(prefix: str, header: bytes) -> bytes:
    return b'\00'.join((_AAD_DOMAIN, prefix.encode('ascii'), header))


def seq_to_id(
    api_type: Any, seq: int | None, location: bytes | int | None = None
) -> str:
    """Given a 64-bit integer, return an encrypted GCIDv2 string."""
    if seq is None:
        raise SequenceError(0, 'sequence is none')

    if type(seq) is not int:
        raise SequenceError(seq, f'invalid type {type(seq)}')

    if seq < 0 or seq >= 2**64:
        raise SequenceError(seq, 'sequence must fit in 64 bits')

    type_prefix = _type_prefix(api_type)
    _validate_wire_prefix(type_prefix)

    seq_bytes = seq.to_bytes(8, 'big')
    id_location = (
        _type_location(api_type)
        if location is None
        else _location_bytes(location)
    )
    plaintext = id_location + seq_bytes
    ciphertext = _aead.encrypt(_NONCE, plaintext, _aad(type_prefix, _HEADER))

    combined = _HEADER + ciphertext
    encoded = base58.b58encode(combined)

    return ''.join((type_prefix, '_', encoded.decode('utf-8')))


def id_type(api_id: str) -> IdType:
    """Return the ID type from the API ID"""
    type_str = _id_prefix(api_id)
    if type_str not in id_rev_map:
        raise IdError(api_id, f'unknown id type: {type_str}')
    return id_rev_map[type_str]


def _decode_id(
    api_id: str, api_id_type: Any, location: bytes | int | None = None
) -> tuple[int, bytes, bytes]:
    if not isinstance(api_id, str):
        raise IdError(api_id, f'IDs must be of string type: {type(api_id)}')

    parts = api_id.split('_')
    if len(parts) != 2:
        raise IdError(api_id, f'ID has invalid format: {api_id}')

    type_str, encoded_id = parts
    if _type_prefix(api_id_type) != type_str:
        raise IdError(api_id, f'ID has invalid type: {type_str}')

    # Base58 decode the obfuscated serial number
    try:
        combined = base58.b58decode(encoded_id)
    except ValueError as exc:
        raise IdError(api_id, 'invalid base58 encoding') from exc

    if len(combined) != _PAYLOAD_BYTES:
        raise IdError(api_id, 'payload byte count mismatch')

    header = combined[:_HEADER_BYTES]
    ciphertext = combined[_HEADER_BYTES:]

    version, suite, schema, key_id = header
    if version != _GCID_VERSION:
        raise IdError(api_id, f'ID has invalid version: {version}')

    if suite != _SUITE_AES_256_GCM_SIV:
        raise IdError(api_id, f'ID has unsupported crypto suite: {suite}')

    if schema != _SCHEMA_SEQ64_LOC56:
        raise IdError(api_id, f'ID has unsupported payload schema: {schema}')

    if key_id != _DEFAULT_KEY_ID:
        raise IdError(api_id, f'ID has unsupported key id: {key_id}')

    try:
        decrypted_data = _aead.decrypt(
            _NONCE, ciphertext, _aad(type_str, header)
        )
    except InvalidTag as exc:
        raise IdError(
            api_id, 'invalid authentication tag or associated data'
        ) from exc

    if len(decrypted_data) != _PLAINTEXT_BYTES:
        raise IdError(api_id, f'Invalid plaintext bytes {len(decrypted_data)}')

    id_location = decrypted_data[:_LOCATION_BYTES]
    seq = decrypted_data[_LOCATION_BYTES:]
    if len(seq) != _SEQ_BYTES:
        raise IdError(api_id, f'Invalid sequence bytes {len(seq)}')

    expected_location = location
    type_location = _type_location(api_id_type)
    if expected_location is None and type_location != _LOCATION_PARTITION:
        expected_location = type_location

    if expected_location is not None:
        expected_location_bytes = _location_bytes(expected_location)
        if id_location != expected_location_bytes:
            raise IdError(api_id, f'ID has invalid location: {id_location}')

    return int.from_bytes(seq, 'big'), _api_id_prefix(id_location), id_location


def id_to_db_seq(
    api_id: str, api_id_type: Any, location: bytes | int | None = None
) -> DbSeq:
    """Validate and decode an encrypted serial number and location."""
    seq, prefix, id_location = _decode_id(api_id, api_id_type, location)
    return DbSeq(
        id_type=api_id_type
        if isinstance(api_id_type, IdType)
        else _type_prefix(api_id_type),
        prefix=prefix,
        seq=seq,
        location=id_location,
    )


def id_to_seq(
    api_id: str, api_id_type: Any, location: bytes | int | None = None
) -> int:
    """Validate and decode an encrypted serial number."""
    return _decode_id(api_id, api_id_type, location)[0]


class Gcid(str):
    """Base class for typed GCID strings."""

    __slots__ = ('_db_seq',)

    name: str = 'gcid'
    prefix: str = ''
    location: bytes | None = None
    accept_seq_in_pydantic: bool = False

    def __new__(cls, value: str | int):
        if cls is Gcid:
            raise TypeError('Gcid must be specialized with typed_id()')

        if isinstance(value, cls):
            return value

        if isinstance(value, int):
            seq = value
            value = seq_to_id(cls, seq)
            id_location = _type_location(cls)
            obj = str.__new__(cls, value)
            obj._db_seq = DbSeq(
                id_type=cls.prefix,
                prefix=_api_id_prefix(id_location),
                seq=seq,
                location=id_location,
            )
            return obj

        if not isinstance(value, str):
            raise IdError(value, f'IDs must be of string type: {type(value)}')

        seq, prefix, id_location = _decode_id(value, cls)
        obj = str.__new__(cls, value)
        obj._db_seq = DbSeq(
            id_type=cls.prefix,
            prefix=prefix,
            seq=seq,
            location=id_location,
        )
        return obj

    @classmethod
    def from_seq(cls, seq: int) -> 'Gcid':
        return cls(seq)

    @property
    def seq(self) -> int:
        return self._db_seq.seq

    @property
    def location_partition(self) -> bytes:
        return self._db_seq.location

    @classmethod
    def to_seq(cls, api_id: str) -> int:
        return id_to_seq(api_id, cls)

    @classmethod
    def validate(cls, value: Any) -> 'Gcid':
        if isinstance(value, cls):
            return value

        if isinstance(value, int) and not cls.accept_seq_in_pydantic:
            raise ValueError(f'{cls.__name__} must be a GCID string')

        try:
            return cls(value)
        except (IdError, SequenceError) as exc:
            raise ValueError(str(exc)) from exc

    @classmethod
    def __get_pydantic_core_schema__(
        cls, source_type: Any, handler: Any
    ) -> core_schema.CoreSchema:
        return core_schema.no_info_plain_validator_function(
            cls.validate,
            serialization=core_schema.plain_serializer_function_ser_schema(
                str, return_schema=core_schema.str_schema()
            ),
        )


def typed_id(
    name: str,
    prefix: str,
    *,
    location: bytes | int | None = None,
    accept_seq_in_pydantic: bool = False,
) -> type[Gcid]:
    """Create a typed GCID class for one application ID kind."""
    if not name.isidentifier():
        raise ValueError(f'id name must be a valid identifier: {name!r}')

    _validate_wire_prefix(prefix)

    class_name = ''.join(part.capitalize() for part in name.split('_')) + 'Id'
    return type(
        class_name,
        (Gcid,),
        {
            '__module__': __name__,
            'name': name,
            'prefix': prefix,
            'location': _location_bytes(location)
            if location is not None
            else None,
            'accept_seq_in_pydantic': accept_seq_in_pydantic,
        },
    )


def registry(**types: str) -> SimpleNamespace:
    """Create an application ID namespace from name=prefix pairs."""
    return SimpleNamespace(
        **{name: typed_id(name, prefix) for name, prefix in types.items()}
    )


def asset_seq_to_id(asset_seq: int) -> str:
    """Convert asset seq to ID"""
    return seq_to_id(IdType.ASSET, asset_seq)


def asset_id_to_seq(asset_id: str) -> int:
    """Convert asset ID to encrypted seq"""
    return id_to_seq(asset_id, IdType.ASSET)


def profile_seq_to_id(profile_seq: int) -> str:
    """Convert asset seq to ID"""
    return seq_to_id(IdType.PROFILE, profile_seq)


def profile_id_to_seq(profile_id: str) -> int:
    """Convert asset ID to encrypted seq"""
    return id_to_seq(profile_id, IdType.PROFILE)


def org_seq_to_id(org_seq: int) -> str:
    """Convert asset seq to ID"""
    return seq_to_id(IdType.ORG, org_seq)


def org_id_to_seq(org_id: str) -> int | None:
    """Convert asset ID to encrypted seq"""
    return id_to_seq(org_id, IdType.ORG)


def file_seq_to_id(file_seq: int) -> str:
    """Convert asset seq to ID"""
    return seq_to_id(IdType.FILE, file_seq)


def file_id_to_seq(file_id: str) -> int:
    """Convert asset ID to encrypted seq"""
    return id_to_seq(file_id, IdType.FILE)


def event_seq_to_id(file_seq: int) -> str:
    """Convert asset seq to ID"""
    return seq_to_id(IdType.EVENT, file_seq)


def event_id_to_seq(file_id: str) -> int:
    """Convert asset ID to encrypted seq"""
    return id_to_seq(file_id, IdType.EVENT)


def topo_seq_to_id(topo_seq: int) -> str:
    """Convert asset seq to ID"""
    return seq_to_id(IdType.TOPO, topo_seq)


def topo_id_to_seq(topo_id: str) -> int:
    """Convert asset ID to encrypted seq"""
    return id_to_seq(topo_id, IdType.TOPO)


def job_def_seq_to_id(job_def_seq: int) -> str:
    """Convert job def seq to ID"""
    return seq_to_id(IdType.JOBDEF, job_def_seq)


def job_def_id_to_seq(job_def_id: str) -> int:
    """Convert job def ID to encrypted seq"""
    return id_to_seq(job_def_id, IdType.JOBDEF)


def job_seq_to_id(job_seq: int) -> str:
    """Convert job seq to ID"""
    return seq_to_id(IdType.JOB, job_seq)


def job_id_to_seq(job_id: str) -> int:
    """Convert job ID to encrypted seq"""
    return id_to_seq(job_id, IdType.JOB)


def job_result_seq_to_id(job_result_seq: int) -> str:
    """Convert job result seq to ID"""
    return seq_to_id(IdType.JOBRESULT, job_result_seq)


def job_result_id_to_seq(job_result_id: str) -> int:
    """Convert job result ID to encrypted seq"""
    return id_to_seq(job_result_id, IdType.JOBRESULT)


def reader_seq_to_id(reader_seq: int) -> str:
    """Convert reader  seq to encrypted ID"""
    return seq_to_id(IdType.READER, reader_seq)


def reader_id_to_seq(reader_id: str) -> int:
    """Convert reader ID to database seq"""
    return id_to_seq(reader_id, IdType.READER)


def tag_seq_to_id(tag_seq: int) -> str:
    """Convert tag seq to encrypted ID"""
    return seq_to_id(IdType.TAG, tag_seq)


def tag_id_to_seq(tag_id: str) -> int:
    """Convert tag ID to database seq"""
    return id_to_seq(tag_id, IdType.TAG)
