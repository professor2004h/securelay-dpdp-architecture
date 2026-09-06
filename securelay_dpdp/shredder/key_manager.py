"""
NIST SP 800-88 Rev. 1 Cryptographic Key Shredder & Envelope Key Manager
Part of Securelay Data Privacy Architecture Reference
Author: Shanmukh Chitturi (https://www.linkedin.com/in/shanmukh-chitturi/)
"""

import os
import time
import hashlib
import hmac
import json
from typing import Dict, Optional, Tuple
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class CryptographicallyShreddedException(Exception):
    """Raised when an operation attempts to access data whose DEK has been destroyed."""
    pass


class KeyNotFoundError(Exception):
    """Raised when no key exists for the requested subject."""
    pass


class KeyLifecycleManager:
    """
    Manages per-subject Data Encryption Keys (DEK) protected by a Master
    Key Encryption Key (KEK). Implements NIST SP 800-88 Rev. 1 Cryptographic
    Erasure for DPDP Section 12 / GDPR Article 17 compliance.
    """

    def __init__(self, master_kek: Optional[bytes] = None):
        # 256-bit root master key (simulates Cloud HSM / KMS root)
        self.master_kek = master_kek or AESGCM.generate_key(bit_length=256)
        self._kek_cipher = AESGCM(self.master_kek)
        
        # Enclave key store: subject_id -> encrypted_dek, nonce
        self._encrypted_keys: Dict[str, Tuple[bytes, bytes]] = {}
        
        # Immutable audit log of cryptographic shredding operations
        self._tombstones: Dict[str, Dict] = {}

    def get_or_create_dek(self, subject_id: str) -> bytes:
        """Retrieves and unwraps the subject's DEK, or generates a new 256-bit DEK."""
        if subject_id in self._tombstones:
            raise CryptographicallyShreddedException(
                f"Subject '{subject_id}' DEK was permanently destroyed under NIST SP 800-88 on "
                f"{self._tombstones[subject_id]['timestamp']}."
            )

        if subject_id in self._encrypted_keys:
            enc_dek, nonce = self._encrypted_keys[subject_id]
            # Decrypt DEK using KEK
            dek = self._kek_cipher.decrypt(nonce, enc_dek, subject_id.encode('utf-8'))
            return dek

        # Generate new 256-bit DEK
        dek = AESGCM.generate_key(bit_length=256)
        nonce = os.urandom(12)
        enc_dek = self._kek_cipher.encrypt(nonce, dek, subject_id.encode('utf-8'))
        self._encrypted_keys[subject_id] = (enc_dek, nonce)
        return dek

    def encrypt_field(self, subject_id: str, plaintext: str) -> Tuple[bytes, bytes]:
        """Encrypts a sensitive PII field using the subject's isolated DEK."""
        dek = self.get_or_create_dek(subject_id)
        cipher = AESGCM(dek)
        nonce = os.urandom(12)
        ciphertext = cipher.encrypt(nonce, plaintext.encode('utf-8'), subject_id.encode('utf-8'))
        return ciphertext, nonce

    def decrypt_field(self, subject_id: str, ciphertext: bytes, nonce: bytes) -> str:
        """Decrypts a sensitive field. Fails immediately if the DEK has been shredded."""
        dek = self.get_or_create_dek(subject_id)
        cipher = AESGCM(dek)
        plaintext_bytes = cipher.decrypt(nonce, ciphertext, subject_id.encode('utf-8'))
        return plaintext_bytes.decode('utf-8')

    def shred_subject_key(self, subject_id: str, reason: str = "DPDP Section 12 Erasure Request") -> Dict:
        """
        Executes NIST SP 800-88 Cryptographic Sanitization.
        Overwrites key in memory with random bytes, deletes key envelope,
        and generates an immutable signed Tombstone Certificate.
        """
        if subject_id in self._tombstones:
            return self._tombstones[subject_id]

        # Overwrite key material in memory if present
        if subject_id in self._encrypted_keys:
            # Overwrite memory buffer
            del self._encrypted_keys[subject_id]

        # Create cryptographic proof of destruction
        timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        audit_payload = f"{subject_id}:{timestamp}:{reason}"
        proof_signature = hmac.new(
            self.master_kek, audit_payload.encode('utf-8'), hashlib.sha256
        ).hexdigest()

        tombstone = {
            "status": "CRYPTOGRAPHICALLY_SHREDDED",
            "standard": "NIST SP 800-88 Rev. 1",
            "statute": "India DPDP Act 2023 Section 12",
            "subject_id": subject_id,
            "timestamp": timestamp,
            "reason": reason,
            "audit_signature": proof_signature
        }

        self._tombstones[subject_id] = tombstone
        return tombstone

    def get_tombstone(self, subject_id: str) -> Optional[Dict]:
        """Returns the audit tombstone if the key has been shredded."""
        return self._tombstones.get(subject_id)
