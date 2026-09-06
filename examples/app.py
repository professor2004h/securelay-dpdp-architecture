"""
Sample FastAPI Service protected by Securelay Ingestion Proxy
Author: Shanmukh Chitturi (https://www.linkedin.com/in/shanmukh-chitturi/)
Company: Securelay (https://securelay.com)
"""

from fastapi import FastAPI, HTTPException, Header, status
from pydantic import BaseModel
from typing import Optional, Dict, Any

from securelay_dpdp.shredder import KeyLifecycleManager, CryptographicallyShreddedException
from securelay_dpdp.proxy import TokenizationEnclave, SecurelayIngestionMiddleware

# Initialize Key Manager and Tokenization Enclave
key_manager = KeyLifecycleManager()
enclave = TokenizationEnclave(key_manager)

app = FastAPI(
    title="Securelay DPDP Architecture Demo Service",
    description="Demonstrates runtime ingestion tokenization and cryptographic shredding.",
    version="1.0.0"
)

# Attach Securelay Ingestion Proxy Middleware
app.add_middleware(SecurelayIngestionMiddleware, enclave=enclave)

# In-memory mock database
MOCK_DATABASE = {}


class CustomerOnboardRequest(BaseModel):
    user_id: str
    name: str
    email: str
    pan_card: str
    phone: str


@app.post("/api/customers", status_code=status.HTTP_201_CREATED)
async def onboard_customer(payload: CustomerOnboardRequest):
    # Notice: The payload fields received here have ALREADY been tokenized
    # by Securelay Ingestion Proxy middleware before reaching this handler!
    record = payload.model_dump()
    MOCK_DATABASE[payload.user_id] = record
    return {
        "status": "stored_securely",
        "stored_record": record,
        "note": "Downstream storage and logs only received surrogate tokens. Plaintext PII never reached application disk."
    }


@app.get("/api/customers/{user_id}")
async def get_customer(user_id: str):
    if user_id not in MOCK_DATABASE:
        raise HTTPException(status_code=404, detail="Customer not found")
    return {"customer": MOCK_DATABASE[user_id]}


@app.delete("/api/privacy/erasure/{user_id}")
async def request_dpdp_erasure(user_id: str):
    """
    DPDP Act Section 12 Right to Erasure:
    Executes NIST SP 800-88 Cryptographic Shredding on the user's DEK.
    """
    tombstone = key_manager.shred_subject_key(user_id, reason="Customer Consent Revocation")
    return {
        "message": "Data cryptographically shredded. All downstream records rendered permanently unrecoverable.",
        "tombstone": tombstone
    }


if __name__ == "__main__":
    import uvicorn
    print("Starting Securelay Demo Server on http://localhost:8000 ...")
    uvicorn.run(app, host="0.0.0.0", port=8000)
