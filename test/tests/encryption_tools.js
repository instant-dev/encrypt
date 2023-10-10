const { expect } = require('chai');
const EncryptionTools = require('../../index.js');

module.exports = () => {

  describe('EncryptionTools', async () => {

    let etClient;
    let etClient2;
    let etServer;
    let decryptEnv;

    it('Should initialize', async () => {

      etClient = new EncryptionTools('alpha', 'beta');
      etClient2 = new EncryptionTools('alpha', 'beta');
      etServer = new EncryptionTools();
      decryptEnv = {};

    });

    it('Should have same secret and iv if initialized with same values', async () => {

      expect(etClient.secret).to.equal(etClient2.secret);
      expect(etClient.iv).to.equal(etClient2.iv);

    });

    it('Should have different secrets and ivs for two instances', async () => {

      expect(etClient.secret).to.not.equal(etServer.secret);
      expect(etClient.iv).to.not.equal(etServer.iv);

    });

    it('Should throw an error if env does not contain __ENV_ENCRYPTION_SECRET and __ENV_ENCRYPTION_IV', async () => {

      let error;

      try {
        const encryptResult = etClient.encryptEnvFileFromPathname('test/dotenv.test_fail');
      } catch (e) {
        error = e;
      }

      expect(error).to.exist;

    });

    it('Should encrypt an env file properly with random secret / iv ', async () => {

      const encryptResult = etServer.encryptEnvFileFromPathname('test/dotenv.random.test');

      expect(encryptResult.file).to.exist;
      expect(encryptResult.json).to.exist;
      expect(Object.keys(encryptResult.json).length).to.equal(3);
      for (const key in encryptResult.json) {
        expect(key).to.satisfy(v => v.startsWith('__ENC_'));
      }
      expect(encryptResult.env).to.exist;
      expect(Object.keys(encryptResult.env).length).to.equal(3);
      expect(encryptResult.env.__ENV_ENCRYPTION_SECRET).to.equal(etServer.secret);
      expect(encryptResult.env.__ENV_ENCRYPTION_IV).to.equal(etServer.iv);
      expect(encryptResult.env.__ENV_ENCRYPTION_METHOD).to.equal(etServer.method);

    });

    it('Should encrypt an env file properly with preset secret / iv', async () => {

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
      expect(encryptResult.env.__ENV_ENCRYPTION_SECRET).to.equal('c4c8c34a55bd64cc4022b3915cf37ce3');
      expect(encryptResult.env.__ENV_ENCRYPTION_IV).to.equal('3d4ea7072b3d6b1d');
      expect(encryptResult.env.__ENV_ENCRYPTION_METHOD).to.equal(etClient.method);
      for (const key in encryptResult.env) {
        decryptEnv[key] = encryptResult.env[key];
      }

    });

    it('Should decrypt an environment properly', async () => {

      const env = etServer.decryptProcessEnv(decryptEnv);

      expect(env).to.exist;
      expect(env).to.equal(decryptEnv);
      expect(Object.keys(env).length).to.equal(6);
      expect(env['MY_VAR']).to.exist;
      expect(env['MY_VAR']).to.equal('104');
      expect(env['MY_OTHER_VAR']).to.exist;
      expect(env['MY_OTHER_VAR']).to.equal('hello world');
      expect(env['MY_LAST_VAR']).to.exist;
      expect(env['MY_LAST_VAR']).to.equal('hello@%20frenz');

    });

    it ('Should encrypt env var in a package of files', async () => {

      const environment = `staging`;
      const files = {
        'index.mjs': Buffer.from(`console.log('hi!');`),
        '.env': Buffer.from([`VAR_1=abc`, `VAR_2=xyz`].join('\n')),
        '.env.staging': Buffer.from([`VAR_1=panic`, `VAR_2=at the`, `VAR_3=disco`].join('\n')),
        '.env.production': Buffer.from([`VAR_1=owl`, `VAR_2=city`, `VAR_3=carly rae`, `VAR_4=jepsen`].join('\n'))
      };

      const packageResult = etServer.encryptEnvFileFromPackage(files, `.env.${environment}`, `.env`, /^\.env\..*$/);

      expect(packageResult.env.__ENV_ENCRYPTION_SECRET).to.equal(etServer.secret);
      expect(packageResult.env.__ENV_ENCRYPTION_IV).to.equal(etServer.iv);
      expect(packageResult.env.__ENV_ENCRYPTION_METHOD).to.equal(etServer.method);
      expect(Object.keys(packageResult.json).length).to.equal(3);
      expect(files).to.equal(packageResult.files);
      expect(Object.keys(files).length).to.equal(2);
      expect(files[`index.mjs`]).to.exist;
      expect(files[`.env`]).to.exist;
      expect(files[`.env`]).to.equal(packageResult.file);

    });

    it ('Should not encrypt env var in a package of files if it is not found', async () => {

      const environment = `preview`;
      const files = {
        'index.mjs': Buffer.from(`console.log('hi!');`),
        '.env': Buffer.from([`VAR_1=abc`, `VAR_2=xyz`].join('\n')),
        '.env.staging': Buffer.from([`VAR_1=panic`, `VAR_2=at the`, `VAR_3=disco`].join('\n')),
        '.env.production': Buffer.from([`VAR_1=owl`, `VAR_2=city`, `VAR_3=carly rae`, `VAR_4=jepsen`].join('\n'))
      };

      const packageResult = etServer.encryptEnvFileFromPackage(files, `.env.${environment}`, `.env`, /^\.env\..*$/);

      expect(Object.keys(packageResult.env).length).to.equal(0);
      expect(Object.keys(packageResult.json).length).to.equal(0);
      expect(files).to.equal(packageResult.files);
      expect(Object.keys(files).length).to.equal(2);
      expect(files[`index.mjs`]).to.exist;
      expect(files[`.env`]).to.exist;
      expect(files[`.env`]).to.equal(packageResult.file);
      expect(files[`.env`].toString()).to.equal('');

    });

  });

};
