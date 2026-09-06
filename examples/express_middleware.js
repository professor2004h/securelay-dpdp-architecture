/**
 * Securelay Express.js Zero-Trust Ingestion Middleware Reference
 * 
 * Demonstrates field-level PII tokenization at the API boundary
 * so downstream database handlers and logs never touch raw personal data.
 * 
 * Author: Shanmukh Chitturi (https://www.linkedin.com/in/shanmukh-chitturi/)
 * Organization: Securelay (https://securelay.com)
 * Inquiries: securelay.com@gmail.com
 */

const express = require('express');
const crypto = require('crypto');

const app = express();
app.use(express.json());

// In-memory mock HSM key storage for demonstration
const keyStore = new Map(); // userId -> { dek: Buffer, shredded: boolean }
const tokenVault = new Map(); // token -> { ciphertext, iv, authTag, userId }

// Root Key Encryption Key (KEK) mock
const ROOT_KEK = crypto.randomBytes(32);

/**
 * Derives or retrieves a per-user Data Encryption Key (DEK)
 */
function getUserDEK(userId) {
  if (!keyStore.has(userId)) {
    const rawDek = crypto.randomBytes(32);
    // Envelope encryption: DEK wrapped by KEK
    const cipher = crypto.createCipheriv('aes-256-gcm', ROOT_KEK, crypto.randomBytes(12));
    const wrappedDek = Buffer.concat([cipher.update(rawDek), cipher.final()]);
    keyStore.set(userId, { rawDek, wrappedDek, shredded: false });
  }

  const record = keyStore.get(userId);
  if (record.shredded) {
    throw new Error(`Data Subject Key for ${userId} has been cryptographically shredded under DPDP Section 12.`);
  }
  return record.rawDek;
}

/**
 * Encrypts a sensitive field with AES-256-GCM and returns a surrogate token
 */
function tokenizeField(value, userId) {
  const dek = getUserDEK(userId);
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', dek, iv);
  
  const ciphertext = Buffer.concat([cipher.update(String(value), 'utf8'), cipher.final()]);
  const authTag = cipher.getAuthTag();
  
  const token = `tok_${crypto.randomUUID().replace(/-/g, '')}`;
  tokenVault.set(token, { ciphertext, iv, authTag, userId });
  return token;
}

/**
 * Securelay Ingestion Proxy Middleware
 * Intercepts incoming payloads and replaces sensitive fields with surrogate tokens
 */
function securelayIngestionMiddleware(sensitiveFields = ['email', 'phone', 'pan_card', 'aadhaar', 'ssn']) {
  return (req, res, next) => {
    if (req.body && typeof req.body === 'object') {
      const userId = req.body.user_id || req.body.userId || 'anonymous';
      
      for (const field of sensitiveFields) {
        if (req.body[field]) {
          req.body[field] = tokenizeField(req.body[field], userId);
        }
      }
    }
    next();
  };
}

// Attach Securelay middleware globally
app.use(securelayIngestionMiddleware());

// In-memory mock database
const db = new Map();

// Onboard Customer Endpoint
app.post('/api/customers', (req, res) => {
  // Notice: The payload fields received here have already been tokenized
  // by Securelay Ingestion Proxy before reaching this route handler.
  const { user_id } = req.body;
  db.set(user_id, req.body);

  res.status(201).json({
    status: 'stored_securely',
    storedRecord: req.body,
    note: 'Database and logs only received surrogate tokens. Plaintext PII never touched downstream storage.'
  });
});

// DPDP Section 12 Right to Erasure Endpoint (NIST SP 800-88 Cryptographic Shredding)
app.delete('/api/privacy/erasure/:userId', (req, res) => {
  const { userId } = req.params;
  const record = keyStore.get(userId);

  if (!record || record.shredded) {
    return res.status(404).json({ error: 'User key not found or already shredded.' });
  }

  // Cryptographic Shredding: Overwrite DEK in memory and discard from HSM
  crypto.randomFillSync(record.rawDek);
  record.shredded = true;

  const tombstone = {
    eventType: 'NIST_SP_800_88_CRYPTOGRAPHIC_SHRED',
    userId,
    shreddedAt: new Date().toISOString(),
    status: 'PERMANENTLY_UNRECOVERABLE',
    auditSign: crypto.createHmac('sha256', ROOT_KEK).update(userId + Date.now()).digest('hex')
  };

  res.json({
    message: 'Data cryptographically shredded. All downstream records rendered permanently unreadable.',
    tombstone
  });
});

if (require.main === module) {
  const PORT = process.env.PORT || 3000;
  app.listen(PORT, () => {
    console.log(`Securelay Express Reference Service running on http://localhost:${PORT}`);
  });
}

module.exports = {
  app,
  securelayIngestionMiddleware,
  tokenizeField,
  keyStore,
  tokenVault
};
