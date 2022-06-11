const axios = require("axios");
const DATA = require("./data");
const {buildQuery} = require("../dist/modules/utils");
const chai = require("chai");


describe("Other implementations", function () {
    this.timeout(60 * 1000);

    it('Device flow', () => {

        function ask(device_code) {
            return axios.post(DATA.AUTHORIZATION_URL + '/oauth/v2/token', buildQuery({
                grant_type: 'urn:ietf:params:oauth:grant-type:device_code',
                client_id: DATA.CLIENT_ID,
                device_code
            }), {
                validateStatus: (s) => true
            });
        }

        const wait = seconds => new Promise(resolve => setTimeout(resolve, seconds * 1000));

        return new Promise(async (resolve, reject) => {
            try {
                // Device code request
                let res = await axios.post(DATA.AUTHORIZATION_URL + '/oauth/v2/device', buildQuery({
                    grant_type: 'token',
                    client_id: DATA.CLIENT_ID,
                    scope: 'scope1'
                }), {
                    validateStatus: (s) => true
                });

                // console.log('CODES:', res.status)

                chai.expect(res.status).to.equal(200);
                chai.expect(res.data.error).to.be.undefined;
                chai.expect(res.data.device_code).to.be.a('string');
                chai.expect(res.data.user_code).to.be.a('string');
                chai.expect(res.data.verification_uri).to.be.a('string');
                chai.expect(res.data.interval).to.be.a('number');
                chai.expect(res.data.expires_in).to.be.a('number');

                const deviceCode = res.data.device_code;

                // Pending
                res = await ask(deviceCode);

                // console.log('PENDING:', res.status, res.data)

                chai.expect(res.status).to.equal(400)
                chai.expect(res.data.error).to.equal('authorization_pending')

                // Slow down
                res = await ask(deviceCode);

                // console.log('SLOW_DOWN:', res.status, res.data)

                chai.expect(res.status).to.equal(400)
                chai.expect(res.data.error).to.equal('slow_down')

                await wait(3);

                // Pending
                res = await ask(deviceCode);

                // console.log('PENDING:', res.status, res.data)

                chai.expect(res.status).to.equal(400)
                chai.expect(res.data.error).to.equal('authorization_pending')

                await wait(3);

                // Tokens
                res = await ask(deviceCode);

                // console.log('TOKENS:', res.status, res.data)

                chai.expect(res.data.error).to.be.undefined;
                chai.expect(res.data.access_token).to.be.a('string');
                chai.expect(res.data.token_type).to.equal('Bearer');
                chai.expect(res.data.expires_in).to.be.a('number');
                chai.expect(res.data.refresh_token).to.be.a('string');
                chai.expect(res.data.scope).to.equal('scope1');

                await wait(3);

                // Not found
                res = await ask(deviceCode);

                // console.log('NOT_FOUND:', res.status, res.data)

                chai.expect(res.status).to.equal(400)
                chai.expect(res.data.error).to.equal('invalid_grant')

                resolve();
            } catch (e) {
                reject(e);
            }
        });
    });
});