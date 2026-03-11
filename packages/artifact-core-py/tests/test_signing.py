"""Tests for Primust Ed25519 signing (Python).

Mirrors the TypeScript test suite for cross-language parity.
"""

import pytest

from primust_artifact_core.signing import generate_key_pair, sign, verify, rotate_key

SIGNER_ID = "signer_test_001"
ORG_ID = "org_test_001"
SIGNER_TYPE = "artifact_signer"


class TestGenerateKeyPair:
    def test_produces_valid_signer_record(self):
        record, private_key = generate_key_pair(SIGNER_ID, ORG_ID, SIGNER_TYPE)

        assert record.signer_id == SIGNER_ID
        assert record.kid.startswith("kid_")
        assert len(record.kid) == 4 + 16  # "kid_" + 16 hex chars
        assert record.algorithm == "Ed25519"
        assert record.status == "active"
        assert record.revocation_reason is None
        assert record.revoked_at is None
        assert record.superseded_by_kid is None
        assert record.org_id == ORG_ID
        assert record.signer_type == SIGNER_TYPE
        assert record.public_key_b64url
        assert len(private_key) == 32

    def test_distinct_kid_each_call(self):
        a, _ = generate_key_pair(SIGNER_ID, ORG_ID, SIGNER_TYPE)
        b, _ = generate_key_pair(SIGNER_ID, ORG_ID, SIGNER_TYPE)

        # Same signer_id
        assert a.signer_id == b.signer_id
        # Different kid
        assert a.kid != b.kid
        # Different key material
        assert a.public_key_b64url != b.public_key_b64url


class TestSignVerifyRoundtrip:
    def test_sign_verify_roundtrip(self):
        record, private_key = generate_key_pair(SIGNER_ID, ORG_ID, SIGNER_TYPE)
        doc = {"action": "create", "target": "resource_42", "ts": "2026-03-10T00:00:00Z"}

        document, envelope = sign(doc, private_key, record)

        assert envelope.signer_id == SIGNER_ID
        assert envelope.kid == record.kid
        assert envelope.algorithm == "Ed25519"
        assert envelope.signature
        assert envelope.signed_at

        assert verify(document, envelope, record.public_key_b64url) is True

    def test_tampered_document_fails_verify(self):
        record, private_key = generate_key_pair(SIGNER_ID, ORG_ID, SIGNER_TYPE)
        doc = {"action": "create", "target": "resource_42"}

        _, envelope = sign(doc, private_key, record)

        tampered = {"action": "delete", "target": "resource_42"}
        assert verify(tampered, envelope, record.public_key_b64url) is False

    def test_wrong_public_key_fails_verify(self):
        record, private_key = generate_key_pair(SIGNER_ID, ORG_ID, SIGNER_TYPE)
        other_record, _ = generate_key_pair("signer_other", ORG_ID, SIGNER_TYPE)
        doc = {"msg": "hello"}

        document, envelope = sign(doc, private_key, record)

        assert verify(document, envelope, other_record.public_key_b64url) is False

    def test_corrupted_signature_fails_verify(self):
        record, private_key = generate_key_pair(SIGNER_ID, ORG_ID, SIGNER_TYPE)
        doc = {"data": "test"}

        document, envelope = sign(doc, private_key, record)

        from dataclasses import replace

        corrupted = replace(envelope, signature="AAAA_bad_signature")
        assert verify(document, corrupted, record.public_key_b64url) is False


class TestSignGuards:
    def test_refuses_to_sign_with_rotated_key(self):
        record, private_key = generate_key_pair(SIGNER_ID, ORG_ID, SIGNER_TYPE)
        from dataclasses import replace

        rotated = replace(record, status="rotated")
        with pytest.raises(ValueError, match="rotated"):
            sign({"data": "test"}, private_key, rotated)

    def test_refuses_to_sign_with_revoked_key(self):
        record, private_key = generate_key_pair(SIGNER_ID, ORG_ID, SIGNER_TYPE)
        from dataclasses import replace

        revoked = replace(record, status="revoked")
        with pytest.raises(ValueError, match="revoked"):
            sign({"data": "test"}, private_key, revoked)


class TestRotateKey:
    def test_rotated_kid_still_verifies_historical_document(self):
        original, private_key = generate_key_pair(SIGNER_ID, ORG_ID, SIGNER_TYPE)
        doc = {"historical": True, "version": 1}

        # Sign with original key
        document, envelope = sign(doc, private_key, original)

        # Rotate the key
        updated, new_record, _ = rotate_key(original)

        # Original is now rotated
        assert updated.status == "rotated"
        assert updated.kid == original.kid
        assert updated.signer_id == SIGNER_ID

        # New record is active under same signer_id
        assert new_record.status == "active"
        assert new_record.signer_id == SIGNER_ID
        assert new_record.kid != original.kid

        # Historical document STILL verifies against old public key
        assert verify(document, envelope, updated.public_key_b64url) is True

    def test_sets_superseded_by_kid_on_old_record(self):
        record, _ = generate_key_pair(SIGNER_ID, ORG_ID, SIGNER_TYPE)
        updated, new_record, _ = rotate_key(record)

        assert updated.superseded_by_kid == new_record.kid
        assert updated.deactivated_at is not None

    def test_preserves_signer_id_across_rotation(self):
        record, _ = generate_key_pair(SIGNER_ID, ORG_ID, SIGNER_TYPE)
        updated, new_record, _ = rotate_key(record)

        assert updated.signer_id == SIGNER_ID
        assert new_record.signer_id == SIGNER_ID

    def test_cannot_rotate_already_rotated_key(self):
        record, _ = generate_key_pair(SIGNER_ID, ORG_ID, SIGNER_TYPE)
        updated, _, _ = rotate_key(record)

        with pytest.raises(ValueError, match="rotated"):
            rotate_key(updated)


class TestQuarantineCompliance:
    def test_no_hardcoded_keys(self):
        keys = [generate_key_pair(SIGNER_ID, ORG_ID, SIGNER_TYPE) for _ in range(5)]
        public_keys = {r.public_key_b64url for r, _ in keys}
        kids = {r.kid for r, _ in keys}

        assert len(public_keys) == 5
        assert len(kids) == 5

    def test_envelope_contains_both_signer_id_and_kid(self):
        record, private_key = generate_key_pair(SIGNER_ID, ORG_ID, SIGNER_TYPE)
        _, envelope = sign({"test": True}, private_key, record)

        assert envelope.signer_id == SIGNER_ID
        assert envelope.kid == record.kid
        assert envelope.signer_id != envelope.kid

    def test_canonical_serialization_is_recursive(self):
        """Q1 enforcement: nested key order must not affect signature."""
        record, private_key = generate_key_pair(SIGNER_ID, ORG_ID, SIGNER_TYPE)

        doc1 = {"outer": {"z": 1, "a": 2}, "id": "test"}
        doc2 = {"id": "test", "outer": {"a": 2, "z": 1}}

        _, sig1 = sign(doc1, private_key, record)

        # doc2 should verify against sig1 because canonical form is identical
        assert verify(doc2, sig1, record.public_key_b64url) is True
