const fs = require('fs');
const os = require('os');
const crypto = require('crypto');

/**
 * Encrypts and decrypts environment variables prefixed with __ENC_
 */
class EncryptionTools {

  constructor (secret, iv) {
    this.secret = this.secretToHex(secret || crypto.randomBytes(64).toString());
    this.iv = this.ivToHex(iv || crypto.randomBytes(64).toString());
    this.method = 'aes-256-cbc';
  }

  secretToHex (secret) {
    return crypto.createHash('sha512').update(secret).digest('hex').slice(0, 32)
  }

  ivToHex (iv) {
    return crypto.createHash('sha512').update(iv).digest('hex').slice(0, 16)
  }

  encrypt (data, secret = null, iv = null, method = null) {
    secret = secret || this.secret;
    iv = iv || this.iv;
    method = method || this.method;
    const cipher = crypto.createCipheriv(method, secret, iv);
    return Buffer.from(cipher.update(data, 'utf8', 'hex') + cipher.final('hex'))
      .toString('base64')
      .replaceAll('=', '_0')
      .replaceAll('+', '_1')
      .replaceAll('/', '_2');
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

  encryptEnvFileFromPackage (files, fromPathname = '.env', toPathname = '.env', deleteRegExp = null, ignoreEnvMismatch = false) {
    let file = null;
    let expectNodeEnv = null;
    let json = {};
    let env = {};
    if (typeof fromPathname !== 'string') {
      throw new Error(`fromPathname must be a string`);
    }
    fromPathname = fromPathname.replaceAll('~', os.homedir());
    if (typeof toPathname !== 'string') {
      throw new Error(`toPathname must be a string`);
    }
    if (
      fromPathname &&
      !ignoreEnvMismatch &&
      fromPathname.match(/(^|\/)\.(.+)\.(.+)$/gi)
    ) {
      expectNodeEnv = fromPathname.replace(/^(.*?\/)?\.(.+)\.(.+)$/gi, '$3');
    }
    toPathname = toPathname.replaceAll('~', os.homedir());
    if (!files || typeof files !== 'object') {
      throw new Error(`files must be object of filename: buffer pairs`);
    }
    if (deleteRegExp) {
      if (!(deleteRegExp instanceof RegExp)) {
        throw new Error(`deleteRegExp must be a valid Regular Expression`)
      }
    }
    if (files[fromPathname]) {
      if (!Buffer.isBuffer(files[fromPathname])) {
        throw new Error(`files["${fromPathname}"] must be a buffer`);
      }
      let encryptResponse = this.encryptEnvFile(files[fromPathname], expectNodeEnv);
      files[toPathname] = file = encryptResponse.file;
      json = encryptResponse.json;
      env = encryptResponse.env;
    } else {
      files[toPathname] = file = Buffer.from('');
    }
    if (deleteRegExp) {
      for (const filename in files) {
        if (filename.match(deleteRegExp)) {
          delete files[filename];
        }
      } 
    }
    return {
      files,
      file,
      json,
      env
    };
  }

  encryptEnvFile (file, expectNodeEnv = null) {
    if (!Buffer.isBuffer(file)) {
      throw new Error(`encryptEnvFile: file must be a buffer`);
    }
    let secret = null;
    let iv = null;
    let method = this.method;
    const foundKeys = {};
    const entries = file.toString()
      .split('\n')
      .map(line => line.trim())
      .filter(v => !!v)
      .map(line => {
        let key = line.split('=')[0];
        let value = line.split('=').slice(1).join('=');
        if (key === 'NODE_ENV' && expectNodeEnv && expectNodeEnv !== value) {
          throw new Error(`Expecting "NODE_ENV=${expectNodeEnv}", found "NODE_ENV=${value}"`);
        } else if (key === '__ENV_ENCRYPTION_SECRET') {
          secret = this.secretToHex(value);
          return null;
        } else if (key === '__ENV_ENCRYPTION_IV') {
          iv = this.ivToHex(value);
          return null;
        } else if (key === '__ENV_ENCRYPTION_METHOD') {
          method = value;
          return null;
        } else if (foundKeys[key]) {
          throw new Error(`Duplicate variable found "${key}", please remove one entry and try again`);
        } else {
          foundKeys[key] = true;
          return {key, value};
        }
      })
      .filter(v => !!v);
    if (!secret && !iv) {
      secret = this.secret;
      iv = this.iv;
    } else if ((!secret && iv) || (secret && !iv)) {
      throw new Error(`Must provide both "__ENV_ENCRYPTION_SECRET" and "__ENV_ENCRYPTION_IV" in the env file to encrypt`);
    }
    const json = {};
    const encLines = entries
      .map(entry => {
        const key = `__ENC_${this.encrypt(entry.key, secret, iv, method)}`;
        const value = this.encrypt(entry.value, secret, iv, method);
        json[key] = value;
        return `${key}=${value}`;
      });
    return {
      file: Buffer.from(encLines.join('\n')),
      json: json,
      env: {
        __ENV_ENCRYPTION_SECRET: secret,
        __ENV_ENCRYPTION_IV: iv,
        __ENV_ENCRYPTION_METHOD: method
      }
    };
  }

  decrypt (encryptedData, secret = null, iv = null, method = null) {
    secret = secret || this.secret;
    iv = iv || this.iv;
    method = method || this.method;
    const buffer = Buffer.from(
      encryptedData
        .replaceAll('_2', '/')
        .replaceAll('_1', '+')
        .replaceAll('_0', '='),
      'base64'
    )
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
        }
        const secret = processEnv.__ENV_ENCRYPTION_SECRET;
        const iv = processEnv.__ENV_ENCRYPTION_IV;
        const method = processEnv.__ENV_ENCRYPTION_METHOD || this.method;
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
    return processEnv;
  }

}

module.exports = EncryptionTools;