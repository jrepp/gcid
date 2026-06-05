import random

import pytest
from pydantic import BaseModel, ValidationError

from gcid.gcid import (
    IdError,
    IdType,
    SequenceError,
    id_to_db_seq,
    id_to_seq,
    id_type,
    registry,
    seq_to_id,
    typed_id,
)


def profile_id():
    """Generate a profile ID"""
    n = 1234567890123456789
    return n, seq_to_id(IdType.PROFILE, n)


def test_round_trip():
    n, api_id = profile_id()
    seq = id_to_seq(api_id, IdType.PROFILE)
    assert seq == n


def test_invalid_type():
    _, api_id = profile_id()
    api_id = api_id.replace('prf', 'foo')
    with pytest.raises(IdError):
        id_to_seq(api_id, IdType.PROFILE)


def test_invalid_format():
    _, api_id = profile_id()
    api_id = api_id.replace('_', ':')
    with pytest.raises(IdError):
        id_to_seq(api_id, IdType.PROFILE)


def test_corrupt_id():
    _, api_id = profile_id()
    with pytest.raises(IdError):
        id_to_seq(api_id[0 : len(api_id) - 1], IdType.PROFILE)


def test_invalid_seq():
    with pytest.raises(SequenceError):
        seq_to_id(IdType.PROFILE, None)


@pytest.mark.parametrize('seq', [-1, 2**64])
def test_sequence_must_fit_in_unsigned_64_bits(seq):
    with pytest.raises(SequenceError):
        seq_to_id(IdType.PROFILE, seq)


@pytest.mark.parametrize('seq', [0, 2**64 - 1])
def test_sequence_boundaries_round_trip(seq):
    api_id = seq_to_id(IdType.PROFILE, seq)

    assert id_to_seq(api_id, IdType.PROFILE) == seq


@pytest.mark.parametrize('seq', [True, 1.0, '1'])
def test_sequence_rejects_non_int_values(seq):
    with pytest.raises(SequenceError):
        seq_to_id(IdType.PROFILE, seq)


def test_multiple():
    enum_values = list(IdType)
    sequences = list(range(2 ^ 32, (2 ^ 32) + 10_000))
    ids = [seq_to_id(random.choice(enum_values), seq) for seq in sequences]
    decoded = [id_to_seq(id, id_type(id)) for id in ids]
    assert sequences == decoded


def test_id_type_rejects_unknown_legacy_prefix():
    with pytest.raises(IdError):
        id_type('unknown_QBt6L5GZA4ob6M8wjQ5MWtgochh')


@pytest.mark.parametrize(
    'api_id',
    [
        '',
        'prf',
        'prf_',
        '_QB',
        'prf_QBt6L5GZA4ob6M8wjQ5MWtgochh_extra',
        'prf_0',
    ],
)
def test_malformed_ids_raise_id_error(api_id):
    with pytest.raises(IdError):
        id_to_seq(api_id, IdType.PROFILE)


def test_invalid_base58_raises_id_error():
    with pytest.raises(IdError):
        id_to_seq('prf_!!!!', IdType.PROFILE)


def test_typed_id_round_trip():
    ProfileId = typed_id('profile', 'prf')

    profile_id = ProfileId(123)

    assert isinstance(profile_id, str)
    assert profile_id.seq == 123
    assert ProfileId.to_seq(profile_id) == 123
    assert ProfileId.from_seq(123) == profile_id


def test_typed_id_reuses_existing_instance():
    ProfileId = typed_id('profile', 'prf')

    profile_id = ProfileId(123)

    assert ProfileId(profile_id) is profile_id


def test_typed_id_rejects_wrong_prefix():
    ProfileId = typed_id('profile', 'prf')
    AssetId = typed_id('asset', 'asset')

    asset_id = AssetId(123)

    with pytest.raises(IdError):
        ProfileId(asset_id)


def test_registry_creates_id_namespace():
    ids = registry(profile='prf', asset='asset')

    profile_id = ids.profile(123)
    asset_id = ids.asset(456)

    assert profile_id.seq == 123
    assert asset_id.seq == 456
    assert ids.profile.to_seq(profile_id) == 123


def test_pydantic_validates_and_serializes_typed_ids():
    ids = registry(profile='prf', asset='asset')

    class Asset(BaseModel):
        id: ids.asset
        owner_id: ids.profile

    asset = Asset(id=ids.asset(1), owner_id=str(ids.profile(2)))

    assert asset.id.seq == 1
    assert asset.owner_id.seq == 2
    assert asset.model_dump() == {
        'id': str(ids.asset(1)),
        'owner_id': str(ids.profile(2)),
    }


def test_pydantic_rejects_wrong_typed_id():
    ids = registry(profile='prf', asset='asset')

    class Asset(BaseModel):
        id: ids.asset

    with pytest.raises(ValidationError):
        Asset(id=ids.profile(1))


def test_pydantic_rejects_raw_seq_by_default():
    ids = registry(asset='asset')

    class Asset(BaseModel):
        id: ids.asset

    with pytest.raises(ValidationError):
        Asset(id=1)


@pytest.mark.parametrize('value', [None, {'id': 'asset_123'}, ['asset_123']])
def test_pydantic_rejects_non_string_shapes(value):
    ids = registry(asset='asset')

    class Asset(BaseModel):
        id: ids.asset

    with pytest.raises(ValidationError):
        Asset(id=value)


def test_pydantic_can_accept_raw_seq_when_enabled():
    AssetId = typed_id('asset', 'asset', accept_seq_in_pydantic=True)

    class Asset(BaseModel):
        id: AssetId

    asset = Asset(id=1)

    assert asset.id.seq == 1


def test_id_can_store_location_partition():
    AssetId = typed_id('asset', 'asset', location=42)

    asset_id = AssetId(123)
    db_seq = id_to_db_seq(asset_id, AssetId)

    assert asset_id.seq == 123
    assert asset_id.location_partition == (42).to_bytes(7, 'big')
    assert db_seq.location == (42).to_bytes(7, 'big')


def test_location_bound_type_rejects_other_locations():
    AssetId = typed_id('asset', 'asset', location=42)
    OtherAssetId = typed_id('asset', 'asset', location=43)

    other_asset_id = OtherAssetId(123)

    with pytest.raises(IdError):
        AssetId(other_asset_id)


def test_location_can_be_overridden_for_generic_conversion():
    api_id = seq_to_id(IdType.ASSET, 123, location=42)

    assert id_to_db_seq(api_id, IdType.ASSET).location == (42).to_bytes(7, 'big')
    assert id_to_seq(api_id, IdType.ASSET, location=42) == 123

    with pytest.raises(IdError):
        id_to_seq(api_id, IdType.ASSET, location=43)


@pytest.mark.parametrize('location', [-1, 2**56])
def test_location_int_must_fit_in_unsigned_56_bits(location):
    with pytest.raises(ValueError):
        typed_id('asset', 'asset', location=location)


@pytest.mark.parametrize('location', [b'', b'123456', b'12345678'])
def test_location_bytes_must_be_seven_bytes(location):
    with pytest.raises(ValueError):
        typed_id('asset', 'asset', location=location)


def test_location_rejects_invalid_type():
    with pytest.raises(TypeError):
        typed_id('asset', 'asset', location='west')


@pytest.mark.parametrize(
    ('name', 'prefix'),
    [
        ('not valid', 'asset'),
        ('asset', ''),
        ('asset', 'bad_prefix'),
    ],
)
def test_typed_id_definition_validation(name, prefix):
    with pytest.raises(ValueError):
        typed_id(name, prefix)
