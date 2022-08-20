const chai = require('chai');
const axios = require("axios");
const DATA = require("./data/data");
const buildQuery = require("../dist/utils/general.utils").buildQuery;


describe("Revocation", function () {
    this.timeout(10 * 1000);

    let tokens;
    it('Request tokens (ROC)', () => {
        return axios.post(DATA.AUTHORIZATION_URL + '/oauth/v2/token', buildQuery({
            grant_type: 'password',
            client_id: DATA.CLIENT_ID,
            client_secret: DATA.CLIENT_SECRET,
            scope: 'scope1',
            username: DATA.USERNAME,
            password: DATA.PASSWORD,
        }), {
            validateStatus: (s) => true
        }).then(res => {
            chai.expect(res.status).to.equal(200);
            chai.expect(res.data.error).to.be.undefined;
            chai.expect(res.data.access_token).to.be.a('string');
            chai.expect(res.data.token_type).to.equal('Bearer');
            chai.expect(res.data.expires_in).to.be.a('number');
            chai.expect(res.data.refresh_token).to.be.a('string');
            chai.expect(res.data.scope).to.equal('scope1');
            tokens = res.data;
        });
    });

    it('Revoke access token', () => {
        return axios.post(DATA.AUTHORIZATION_URL + '/oauth/v2/revocation', {
            client_id: DATA.CLIENT_ID,
            client_secret: DATA.CLIENT_SECRET,
            token: tokens.access_token
        }, {
            validateStatus: (status) => true
        }).then(res => {
            chai.expect(res.status).to.equal(200);
        });
    });

    it('No scope', () => {
        return axios.get(DATA.AUTHORIZATION_URL + '/protected', {
            headers: {
                Authorization: `Bearer ${tokens.access_token}`
            },
            validateStatus: (status) => true
        }).then(res => {
            chai.expect(res.status).to.equal(401);
            chai.expect(res.data.error).to.equal('invalid_token');
            chai.expect(res.data.error_description).to.equal('The access token has expired');
        });
    });

    it('Revoke refresh token', () => {
        return axios.post(DATA.AUTHORIZATION_URL + '/oauth/v2/revocation', {
            client_id: DATA.CLIENT_ID,
            client_secret: DATA.CLIENT_SECRET,
            token: tokens.refresh_token
        }, {
            validateStatus: (status) => true
        }).then(res => {
            chai.expect(res.status).to.equal(200);
        });
    });

    it('Refresh Token', () => {
        return axios.post(DATA.AUTHORIZATION_URL + '/oauth/v2/token',
            'grant_type=refresh_token'
            + `&client_id=${DATA.CLIENT_ID}`
            + `&client_secret=${DATA.CLIENT_SECRET}`
            + `&refresh_token=${tokens.refresh_token}`, {
                validateStatus: (s) => true
            }).then(res => {
            chai.expect(res.status).to.equal(400);
            chai.expect(res.data.error).to.equal('invalid_grant');
            chai.expect(res.data.error_description).to.equal('The refresh token has expired');
        });
    });
});