const { expect } = require('chai');
const EncryptionTools = require('../../index.js');

module.exports = () => {

  describe('EncryptionTools', async () => {

    let etClient;
    let etServer;
    let decryptEnv;

    it('Should initialize', async () => {

      etClient = new EncryptionTools();
      etServer = new EncryptionTools();
      decryptEnv = {};

    });

    it('Should have different secrets and ivs for two instances', async () => {

      expect(etClient.secret).to.not.equal(etServer.secret);
      expect(etClient.iv).to.not.equal(etServer.iv);

    });

    it('Should encrypt an env file properly', async () => {

      const encryptResult = etClient.encryptEnvFileFromPathname('test/dotenv.test');

      expect(encryptResult.file).to.exist;
      expect(encryptResult.json).to.exist;
      expect(Object.keys(encryptResult.json).length).to.equal(3);
      for (const key in encryptResult.json) {
        expect(key).to.satisfy(v => v.startsWith('__ENC_'));
        decryptEnv[key] = encryptResult.json[key];
      }
      expect(encryptResult.env).to.exist;
      expect(Object.keys(encryptResult.env).length).to.equal(3);
      expect(encryptResult.env.__ENV_ENCRYPTION_SECRET).to.equal(etClient.secret);
      expect(encryptResult.env.__ENV_ENCRYPTION_IV).to.equal(etClient.iv);
      expect(encryptResult.env.__ENV_ENCRYPTION_METHOD).to.equal(etClient.method);
      for (const key in encryptResult.env) {
        decryptEnv[key] = encryptResult.env[key];
      }

    });

    it('Should decrypt an environment properly', async () => {

      const env = etServer.decryptProcessEnv(decryptEnv);

      expect(env).to.exist;
      expect(env).to.equal(decryptEnv);
      expect(Object.keys(env).length).to.equal(3);
      expect(env['MY_VAR']).to.exist;
      expect(env['MY_VAR']).to.equal('104');
      expect(env['MY_OTHER_VAR']).to.exist;
      expect(env['MY_OTHER_VAR']).to.equal('hello world');
      expect(env['MY_$LAST$_VAR']).to.exist;
      expect(env['MY_$LAST$_VAR']).to.equal('hello@%20frenz');

    });

  });

};
