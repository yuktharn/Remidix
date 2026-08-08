// tokenCrypto.js
// Encrypts/decrypts GitHub/GitLab personal access tokens before they touch
// the database. Uses AES-256-GCM (authenticated encryption — a tampered
// ciphertext fails to decrypt instead of silently returning garbage).
//
// Requires TOKEN_ENCRYPTION_KEY in .env: a 64-character hex string (32 bytes).
// Generate one with:
//   node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
// Treat it like any other secret — never commit it, rotate it if it leaks.

const crypto = require("crypto");

const ALGORITHM = "aes-256-gcm";

function getKeyBuffer() {
  const key = process.env.TOKEN_ENCRYPTION_KEY;
  if (!key || key.length !== 64) {
    throw new Error(
      "TOKEN_ENCRYPTION_KEY must be set in .env as a 64-character hex string (32 bytes)."
    );
  }
  return Buffer.from(key, "hex");
}

// Returns { encryptedToken, iv, authTag } — all hex strings, safe to store
// as-is in three separate columns.
function encryptToken(plainToken) {
  const iv = crypto.randomBytes(12); // 96-bit IV, recommended for GCM
  const cipher = crypto.createCipheriv(ALGORITHM, getKeyBuffer(), iv);
  const encrypted = Buffer.concat([cipher.update(plainToken, "utf8"), cipher.final()]);
  const authTag = cipher.getAuthTag();

  return {
    encryptedToken: encrypted.toString("hex"),
    iv: iv.toString("hex"),
    authTag: authTag.toString("hex"),
  };
}

// Reverses encryptToken(). Throws if the auth tag doesn't match (tampered
// or wrong key) — always wrap this in try/catch at the call site.
function decryptToken(encryptedTokenHex, ivHex, authTagHex) {
  const decipher = crypto.createDecipheriv(ALGORITHM, getKeyBuffer(), Buffer.from(ivHex, "hex"));
  decipher.setAuthTag(Buffer.from(authTagHex, "hex"));
  const decrypted = Buffer.concat([
    decipher.update(Buffer.from(encryptedTokenHex, "hex")),
    decipher.final(),
  ]);
  return decrypted.toString("utf8");
}

module.exports = { encryptToken, decryptToken };