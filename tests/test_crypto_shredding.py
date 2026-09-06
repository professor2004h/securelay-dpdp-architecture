import pytest
from securelay_dpdp.shredder.key_manager import (
    KeyLifecycleManager,
    CryptographicallyShreddedException
)


def test_encryption_and_decryption():
    km = KeyLifecycleManager()
    subject_id = "usr_1001"
    secret_data = "PAN_ABCDE1234F_SECRET"

    ciphertext, nonce = km.encrypt_field(subject_id, secret_data)
    assert ciphertext != secret_data.encode("utf-8")

    decrypted = km.decrypt_field(subject_id, ciphertext, nonce)
    assert decrypted == secret_data


def test_key_isolation_between_subjects():
    km = KeyLifecycleManager()
    c1, n1 = km.encrypt_field("usr_1", "DATA_1")
    c2, n2 = km.encrypt_field("usr_2", "DATA_2")

    # Attempting to decrypt usr_1 ciphertext with usr_2 key must fail
    with pytest.raises(Exception):
        km.decrypt_field("usr_2", c1, n1)


def test_nist_sp_800_88_cryptographic_shredding():
    km = KeyLifecycleManager()
    subject_id = "usr_erasure_target"
    secret_aadhaar = "9988-7766-5544"

    ciphertext, nonce = km.encrypt_field(subject_id, secret_aadhaar)
    assert km.decrypt_field(subject_id, ciphertext, nonce) == secret_aadhaar

    # Execute NIST SP 800-88 cryptographic shredding
    tombstone = km.shred_subject_key(subject_id, reason="DPDP Section 12 User Request")
    assert tombstone["status"] == "CRYPTOGRAPHICALLY_SHREDDED"
    assert tombstone["standard"] == "NIST SP 800-88 Rev. 1"
    assert "audit_signature" in tombstone
    assert len(tombstone["audit_signature"]) == 64

    # Subsequent decryption MUST raise CryptographicallyShreddedException
    with pytest.raises(CryptographicallyShreddedException):
        km.decrypt_field(subject_id, ciphertext, nonce)

    # Key generation for shredded user MUST also be blocked
    with pytest.raises(CryptographicallyShreddedException):
        km.get_or_create_dek(subject_id)
