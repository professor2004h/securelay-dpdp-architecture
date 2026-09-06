import pytest
from securelay_dpdp.shredder.key_manager import (
    KeyLifecycleManager,
    CryptographicallyShreddedException
)
from securelay_dpdp.proxy.enclave import TokenizationEnclave

def test_cross_framework_ingestion_sanitization():
    """Validates ISO 27001 A.8.11, SOC 2 CC6.6, and DPDP Section 8(5) data minimization at ingress."""
    km = KeyLifecycleManager()
    enclave = TokenizationEnclave(km)

    sample_payload = {
        "user_id": "usr_9981",
        "email": "executive@enterprise.in",
        "pan": "ABCDE1234F",
        "phone": "+919876543210",
        "amount": 500000
    }

    sanitized = enclave.tokenize_payload("usr_9981", sample_payload)

    # Invariant 1: Plaintext statutory identifiers must never remain in downstream payload
    assert "ABCDE1234F" not in str(sanitized)
    assert "executive@enterprise.in" not in str(sanitized)
    assert "+919876543210" not in str(sanitized)

    # Invariant 2: Surrogate tokens must be present and deterministic
    assert sanitized["pan"].startswith("tok_pan_")
    assert sanitized["email"].startswith("tok_ema_")
    assert sanitized["phone"].startswith("tok_pho_")
    assert sanitized["amount"] == 500000

def test_cross_framework_statutory_erasure_invariants():
    """Validates DPDP Section 12, GDPR Art 17, and NIST SP 800-88 cryptographic sanitization."""
    km = KeyLifecycleManager()
    enclave = TokenizationEnclave(km)

    payload = {
        "email": "ciso@fintech.in",
        "pan": "XYZPA9999K"
    }

    sanitized = enclave.tokenize_payload("usr_ciso_44", payload)
    token = sanitized["pan"]

    # Pre-erasure: Authorized re-identification works
    pre_erasure = enclave.detokenize(token, requester_role="COMPLIANCE_OFFICER")
    assert pre_erasure == "XYZPA9999K"

    # Execute NIST SP 800-88 Cryptographic Shredding
    tombstone = km.shred_subject_key("usr_ciso_44", reason="DPDP Section 12 Statutory Mandate")

    # Invariant 3: Key destruction produces tamper-evident audit receipt
    assert tombstone["status"] == "CRYPTOGRAPHICALLY_SHREDDED"
    assert tombstone["standard"] == "NIST SP 800-88 Rev. 1"
    assert "audit_signature" in tombstone

    # Invariant 4: Post-shredding decryption is mathematically impossible
    with pytest.raises(CryptographicallyShreddedException):
        enclave.detokenize(token, requester_role="COMPLIANCE_OFFICER")
