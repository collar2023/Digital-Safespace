// --- DigitalSafe-Crypto-Core.js ---
// MIT License - Copyright (c) [Your Name/Company Name] [Year]

/**
 * DIGITAL SAFE: END-TO-END ENCRYPTION (E2EE) CRYPTO CORE
 * This file contains the cryptographic functions used by the client for E2EE.
 * It is provided for transparency and community audit purposes only.
 * The core server logic, including rate limiting and session management, is private.
 */

const VERIFY_CODE = "HANDSHAKE_OK_V2";
const enc = new TextEncoder();

/**
 * Derives a strong encryption key from the user's secret password (pass) 
 * using PBKDF2 with 100,000 iterations and SHA-256 hash.
 * @param {string} password The user-provided secret key.
 * @returns {Promise<CryptoKey>} The derived key for AES-GCM.
 */
async function deriveKey(password) {
  const material = await crypto.subtle.importKey("raw", enc.encode(password), "PBKDF2", false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    { 
      name: "PBKDF2", 
      salt: enc.encode("SIMPLE_SALT_V2"), 
      iterations: 100000, 
      hash: "SHA-256" 
    },
    material, 
    { name: "AES-GCM", length: 256 }, // AES-256 GCM 
    false, 
    ["encrypt", "decrypt"]
  );
}

/**
 * Encrypts a plaintext message using AES-256 GCM.
 * @param {string} text The message to encrypt.
 * @param {CryptoKey} key The derived AES key.
 * @returns {Promise<string>} JSON string containing the IV and the ciphertext data.
 */
async function encrypt(text, key) {
  const iv = crypto.getRandomValues(new Uint8Array(12)); // 12-byte IV for GCM
  const encoded = enc.encode(text);
  const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, encoded);
  return JSON.stringify({ iv: Array.from(iv), data: Array.from(new Uint8Array(ciphertext)) });
}

/**
 * Decrypts a JSON payload into a plaintext string.
 * @param {string} jsonStr The JSON string containing IV and ciphertext.
 * @param {CryptoKey} key The derived AES key.
 * @returns {Promise<string | null>} The decrypted plaintext, or null on error (e.g., wrong key).
 */
async function decrypt(jsonStr, key) {
  try {
    const body = JSON.parse(jsonStr);
    const iv = new Uint8Array(body.iv);
    const data = new Uint8Array(body.data);
    const decrypted = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, data);
    return new TextDecoder().decode(decrypted);
  } catch(e) { 
    // Decrypt failures (e.g., wrong key or corrupted IV) result in null.
    return null; 
  }
}

// Optional: Export these functions if you structure your frontend code with modules.
// export { deriveKey, encrypt, decrypt, VERIFY_CODE };