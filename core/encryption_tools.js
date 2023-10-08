const fs = require('fs');
const os = require('os');
const crypto = require('crypto');

/**
 * Encrypts and decrypts environment variables prefixed with __ENC_
 */
class EncryptionTools {

  constructor () {
    this.method = 'aes-256-cbc';
    this.secret = crypto.randomBytes(64).toString('hex').slice(0, 32);
    this.iv = crypto.randomBytes(64).toString('hex').slice(0, 16);
  }

  encrypt (data) {
    const cipher = crypto.createCipheriv(this.method, this.secret, this.iv)
    return Buffer.from(
      cipher.update(data, 'utf8', 'hex') + cipher.final('hex')
    ).toString('base64').replaceAll('=', '$');
  }

  encryptEnvFileFromPathname (pathname) {
    if (typeof pathname !== 'string') {
      throw new Error(`pathname must be a string`);
    }
    pathname = pathname.replaceAll('~', os.homedir());
    if (!fs.existsSync(pathname)) {
      throw new Error(`pathname "${pathname}" does not exist`);
    } else if (fs.statSync(pathname).isDirectory()) {
      throw new Error(`pathname "${pathname}" is not a valid file`);
    }
    const file = fs.readFileSync(pathname);
    return this.encryptEnvFile(file);
  }

  encryptEnvFile (file) {
    if (!Buffer.isBuffer(file)) {
      throw new Error(`encryptEnvFile: file must be a buffer`);
    }
    const foundKeys = {};
    const entries = file.toString()
      .split('\n')
      .map(line => line.trim())
      .filter(v => !!v)
      .map(line => {
        let key = line.split('=')[0];
        let value = line.split('=').slice(1).join('=');
        if (foundKeys[key]) {
          throw new Error(`Duplicate variable found "${key}", please remove one entry and try again`);
        }
        foundKeys[key] = true;
        return {key, value};
      });
    const json = {};
    const encLines = entries
      .map(entry => {
        const key = `__ENC_${this.encrypt(entry.key)}`;
        const value = this.encrypt(entry.value);
        json[key] = value;
        return `${key}=${value}`;
      });
    return {
      file: Buffer.from(encLines.join('\n')),
      json: json,
      env: {
        __ENV_ENCRYPTION_SECRET: this.secret,
        __ENV_ENCRYPTION_IV: this.iv,
        __ENV_ENCRYPTION_METHOD: this.method
      }
    };
  }

  decrypt (encryptedData, secret = null, iv = null, method = null) {
    secret = secret || this.secret;
    iv = iv || this.iv;
    method = method || this.method;
    const buffer = Buffer.from(encryptedData.replaceAll('$', '='), 'base64')
    const decipher = crypto.createDecipheriv(method, secret, iv)
    return (
      decipher.update(buffer.toString('utf8'), 'hex', 'utf8') +
      decipher.final('utf8')
    );
  }

  decryptProcessEnv (processEnv) {
    for (const key in processEnv) {
      if (key.startsWith('__ENC_')) {
        const encKeyName = key.slice('__ENC_'.length);
        const encKeyValue = processEnv[key];
        delete processEnv[key];
        if (!processEnv.__ENV_ENCRYPTION_SECRET) {
          throw new Error(`Missing process.env["__ENV_ENCRYPTION_SECRET"]`);
        } else if (!processEnv.__ENV_ENCRYPTION_IV) {
          throw new Error(`Missing process.env["__ENV_ENCRYPTION_IV"]`);
        } else if (!processEnv.__ENV_ENCRYPTION_METHOD) {
          throw new Error(`Missing process.env["__ENV_ENCRYPTION_METHOD"]`);
        }
        const secret = processEnv.__ENV_ENCRYPTION_SECRET;
        const iv = processEnv.__ENV_ENCRYPTION_IV;
        const method = processEnv.__ENV_ENCRYPTION_METHOD;
        try {
          const keyName = this.decrypt(encKeyName, secret, iv, method);
          const keyValue = this.decrypt(encKeyValue, secret, iv, method);
          processEnv[keyName] = keyValue;
        } catch (e) {
          console.error(e);
          throw new Error(`Could not decrypt: ${e.message}`);
        }
      }
    }
    delete processEnv.__ENV_ENCRYPTION_SECRET;
    delete processEnv.__ENV_ENCRYPTION_IV;
    delete processEnv.__ENV_ENCRYPTION_METHOD;
    return processEnv;
  }

}

module.exports = EncryptionTools;