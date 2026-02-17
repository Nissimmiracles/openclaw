/**
 * Encryption Tests
 */

import { describe, it, expect } from '@jest/globals';
import { EncryptionManager } from '../../src/security/encryption';

describe('EncryptionManager', () => {
  let encryptionManager: EncryptionManager;

  beforeEach(() => {
    encryptionManager = new EncryptionManager();
  });

  describe('Field Encryption', () => {
    it('should encrypt and decrypt field', async () => {
      const plaintext = 'sensitive-api-key';
      const fieldName = 'api_key';

      const encrypted = await encryptionManager.encryptField(
        plaintext,
        fieldName
      );
      expect(encrypted).not.toBe(plaintext);

      const decrypted = await encryptionManager.decryptField(
        encrypted,
        fieldName
      );
      expect(decrypted).toBe(plaintext);
    });

    it('should produce different ciphertext for same plaintext', async () => {
      const plaintext = 'sensitive-data';

      const encrypted1 = await encryptionManager.encryptField(
        plaintext,
        'field1'
      );
      const encrypted2 = await encryptionManager.encryptField(
        plaintext,
        'field2'
      );

      expect(encrypted1).not.toBe(encrypted2);
    });

    it('should fail decryption with wrong key', async () => {
      const plaintext = 'sensitive-data';
      const encrypted = await encryptionManager.encryptField(
        plaintext,
        'field1'
      );

      // Attempting to decrypt with wrong field name (different key derivation)
      await expect(
        encryptionManager.decryptField(encrypted, 'wrong-field')
      ).rejects.toThrow();
    });
  });

  describe('Object Encryption', () => {
    it('should encrypt and decrypt object', async () => {
      const obj = {
        name: 'John Doe',
        email: 'john@example.com',
        apiKey: 'secret-key',
      };

      const encrypted = await encryptionManager.encryptObject(obj);
      expect(encrypted.name).not.toBe(obj.name);

      const decrypted = await encryptionManager.decryptObject(encrypted);
      expect(decrypted).toEqual(obj);
    });

    it('should handle nested objects', async () => {
      const obj = {
        user: {
          name: 'John',
          credentials: {
            apiKey: 'secret',
          },
        },
      };

      const encrypted = await encryptionManager.encryptObject(obj);
      const decrypted = await encryptionManager.decryptObject(encrypted);

      expect(decrypted).toEqual(obj);
    });
  });

  describe('Key Rotation', () => {
    it('should rotate encryption key', async () => {
      const plaintext = 'test-data';

      // Encrypt with old key
      const encrypted = await encryptionManager.encryptField(
        plaintext,
        'field1'
      );

      // Rotate key
      await encryptionManager.rotateKeys();

      // Should still be able to decrypt old data
      const decrypted = await encryptionManager.decryptField(
        encrypted,
        'field1'
      );
      expect(decrypted).toBe(plaintext);
    });

    it('should use new key for new encryptions after rotation', async () => {
      const plaintext = 'test-data';

      const encrypted1 = await encryptionManager.encryptField(
        plaintext,
        'field1'
      );

      await encryptionManager.rotateKeys();

      const encrypted2 = await encryptionManager.encryptField(
        plaintext,
        'field1'
      );

      // Should be different ciphertexts (different keys)
      expect(encrypted1).not.toBe(encrypted2);
    });
  });
});
