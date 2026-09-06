import pytest
from securelay_dpdp.shredder.key_manager import KeyLifecycleManager, CryptographicallyShreddedException
from securelay_dpdp.proxy.enclave import TokenizationEnclave


def test_payload_tokenization():
    km = KeyLifecycleManager()
    enclave = TokenizationEnclave(km)

    raw_payload = {
        "user_id": "usr_9921",
        "name": "Priya Patel",
        "email": "priya@enterprise.in",
        "pan_card": "ABCDE1234F",
        "phone": "+919876543210",
        "metadata": {
            "tier": "enterprise",
            "medical_record": "MED-REC-88410"
        }
    }

    sanitized = enclave.tokenize_payload("usr_9921", raw_payload)

    # Non-sensitive fields stay unchanged
    assert sanitized["user_id"] == "usr_9921"
    assert sanitized["name"] == "Priya Patel"
    assert sanitized["metadata"]["tier"] == "enterprise"

    # Sensitive fields are replaced by surrogate tokens
    assert sanitized["email"].startswith("tok_ema_")
    assert sanitized["pan_card"].startswith("tok_pan_")
    assert sanitized["phone"].startswith("tok_pho_")
    assert sanitized["metadata"]["medical_record"].startswith("tok_med_")

    # Detokenization with authorized role works
    email_plain = enclave.detokenize(sanitized["email"], requester_role="COMPLIANCE_OFFICER")
    assert email_plain == "priya@enterprise.in"

    # Unauthorized detokenization rejected
    with pytest.raises(PermissionError):
        enclave.detokenize(sanitized["email"], requester_role="INTERN")


def test_tokenization_invalidated_upon_shredding():
    km = KeyLifecycleManager()
    enclave = TokenizationEnclave(km)

    raw_payload = {
        "email": "lead@bank.com",
        "pan": "BNZPA1234K"
    }
    sanitized = enclave.tokenize_payload("usr_bank_01", raw_payload)
    token = sanitized["pan"]

    # Verify initial detokenization
    assert enclave.detokenize(token, requester_role="COMPLIANCE_OFFICER") == "BNZPA1234K"

    # Shred the subject's cryptographic key
    km.shred_subject_key("usr_bank_01")

    # Detokenization now mathematically fails
    with pytest.raises(CryptographicallyShreddedException):
        enclave.detokenize(token, requester_role="COMPLIANCE_OFFICER")
