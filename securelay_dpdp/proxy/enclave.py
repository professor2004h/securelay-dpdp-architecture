"""
Securelay Tokenization Enclave Shim
Performs high-speed field-level tokenization and envelope encryption
Author: Shanmukh Chitturi (https://www.linkedin.com/in/shanmukh-chitturi/)
"""

import base64
import uuid
from typing import Dict, Any, List, Set, Tuple
from ..shredder.key_manager import KeyLifecycleManager, CryptographicallyShreddedException


class TokenizationEnclave:
    """
    Enclave service responsible for intercepting sensitive fields and replacing
    them with non-reversible surrogate tokens before forwarding to microservices.
    """

    DEFAULT_SENSITIVE_FIELDS: Set[str] = {
        "pan", "pan_card", "aadhaar", "ssn", "phone", "email",
        "passport", "credit_card", "cvv", "medical_record"
    }

    def __init__(self, key_manager: KeyLifecycleManager, sensitive_fields: Set[str] = None):
        self.key_mgr = key_manager
        self.sensitive_fields = sensitive_fields or self.DEFAULT_SENSITIVE_FIELDS
        
        # In-enclave vault: token -> (subject_id, field_name, ciphertext, nonce)
        self._vault: Dict[str, Tuple[str, str, bytes, bytes]] = {}

    def tokenize_payload(self, subject_id: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        """
        Recursively inspects a JSON-like payload and replaces sensitive fields
        with surrogate tokens.
        """
        sanitized = {}
        for k, v in payload.items():
            if isinstance(v, dict):
                sanitized[k] = self.tokenize_payload(subject_id, v)
            elif isinstance(v, list):
                sanitized[k] = [
                    self.tokenize_payload(subject_id, item) if isinstance(item, dict) else item
                    for item in v
                ]
            elif k.lower() in self.sensitive_fields and isinstance(v, str):
                token = self._tokenize_field(subject_id, k, v)
                sanitized[k] = token
            else:
                sanitized[k] = v
        return sanitized

    def _tokenize_field(self, subject_id: str, field_name: str, plaintext_value: str) -> str:
        """Encrypts value with subject DEK and returns a surrogate token."""
        ciphertext, nonce = self.key_mgr.encrypt_field(subject_id, plaintext_value)
        token_id = f"tok_{field_name[:3]}_{uuid.uuid4().hex[:12]}"
        self._vault[token_id] = (subject_id, field_name, ciphertext, nonce)
        return token_id

    def detokenize(self, token: str, requester_role: str = "COMPLIANCE_OFFICER") -> str:
        """
        Detokenizes a surrogate token back to plaintext.
        Strictly requires elevated role and valid un-shredded DEK.
        """
        if requester_role not in {"COMPLIANCE_OFFICER", "SYSTEM_ENCLAVE_READ"}:
            raise PermissionError(f"Role '{requester_role}' not authorized to detokenize PII.")

        if token not in self._vault:
            raise KeyError(f"Token '{token}' not recognized in enclave vault.")

        subject_id, field_name, ciphertext, nonce = self._vault[token]
        # This will raise CryptographicallyShreddedException if shredded!
        return self.key_mgr.decrypt_field(subject_id, ciphertext, nonce)
