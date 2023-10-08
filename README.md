# Simple encryption for Environment variables
![npm version](https://img.shields.io/npm/v/@instant.dev/encrypt?label=) ![Build Status](https://app.travis-ci.com/instant-dev/encrypt.svg?branch=main)

## Encrypt environment variables

This package provides simple encryption / decryption methods, specialized for
managing `.env` plaintext files in deployments, to prevent plaintext storage on
your web server. This is only meant to prevent an attacker with filesystem access
from reading your secrets; it's up to you to store the encryption secret,
initialization vector (iv) and method separately. We recommend using your cloud
hosts manual environment variable management to store `__ENV_ENCRYPTION_SECRET`,
`__ENV_ENCRYPTION_IV` and `__ENV_ENCRYPTION_METHOD` which are used to decrypt the
encrypted file.

**Note:** If you store the encryption secret, iv and method in plaintext as part
of environment variables, then the attack surface area is anyone with administrative
access to your server environment or the ability to execute code. This encryption
is **only** meant to prevent those with filesystem access from reading your secrets.

## How it works

We create an alternate `.env` file that looks like this;

```
__ENC_MTRiMjliNzc3MWQxZDAyMWI5YTRiNTdhNjk5OWMwN2E$=ZWMzOTMwY2U5YWEyNTkwODJhOTY4ZjhkMTM3YzBhNmQ$
__ENC_ZjAwYzliM2RhZGVhMjdkZWJiNzYyODcxNjhmMzQ2MjI$=YjE1OTVmYTgxMWRiZjgzOGRiNGNjNjMwODM5YzFjN2Y$
__ENC_NWViMzg3NzhhZWNmN2RmNzg4M2UzY2Y4ZGZiNTNmMzc$=OGZiM2IwZDY0YmUyOTE3MzM3NGEwN2NiOWZlNjI4M2U$
```

These variables should then be loaded into `process.env` either using `dotenv` or the
Node 20 built-in env loader. They can then be decrypted on process boot via:

```javascript
const et = new EncryptionTools();
et.decryptProcessEnv(process.env);
```

And that's it! You'll want to make sure `__ENV_ENCRYPTION_SECRET`,
`__ENV_ENCRYPTION_IV` and `__ENV_ENCRYPTION_METHOD` are set in `process.env` available
on boot. The [instant.dev](https://github.com/instant-dev/instant) deployment tools,
[@instant.dev/deploy](https://github.com/instant-dev/deploy) will do this automatically.

Encrypting env vars while deploying:

```javascript
const EncryptionTools = require('@instant.dev/encrypt');
const et = new EncryptionTools();

// When deploying to "staging" environment
const encryptResult = et.encryptEnvFileFromPathname('.env.staging');
// encryptResult.file is the file buffer
addToPackagedFiles('.env', encryptResult.file);
// encryptResult.env contains:
// __ENV_ENCRYPTION_SECRET: "..."
// __ENV_ENCRYPTION_IV: "..."
// __ENV_ENCRYPTION_METHOD: "..."
updateEnvVars(encryptResult.env);
```

Then decrypting server-side, if vars are store in `.env`:

```javascript
const dotenv = require('dotenv');
dotenv.config();
et.decryptProcessEnv(process.env);
```

## Acknowledgements

Special thank you to [Scott Gamble](https://x.com/threesided) who helps run all
of the front-of-house work for instant.dev 💜!

| Destination | Link |
| ----------- | ---- |
| Home | [instant.dev](https://instant.dev) |
| GitHub | [github.com/instant-dev](https://github.com/instant-dev) |
| Discord | [discord.gg/puVYgA7ZMh](https://discord.gg/puVYgA7ZMh) |
| X / instant.dev | [x.com/instantdevs](https://x.com/instantdevs) |
| X / Keith Horwood | [x.com/keithwhor](https://x.com/keithwhor) |
| X / Scott Gamble | [x.com/threesided](https://x.com/threesided) |