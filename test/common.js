const chai = require('chai');
const axios = require("axios");
const DATA = require("./data/data");
const express = require("express");
const buildQuery = require("../dist/utils/general.utils").buildQuery;

const clientExpress = express();
clientExpress.get('/callback', (req, res) => {
    res.status(200).json({
        message: 'success',
        tokens: req.query
    });
});

const server = clientExpress.listen(DATA.CLIENT_IMPLICIT_PORT, () => {
    console.log('Client implicit server listening at', DATA.CLIENT_IMPLICIT_PORT);
});

setTimeout(server.close.bind(server), 60 * 1000);

describe("Common flows", function () {
    this.timeout(10 * 1000);

    it('Implicit', () => {
        return axios.get(DATA.AUTHORIZATION_URL + '/oauth/v2/authorize?' + buildQuery({
            response_type: 'token',
            client_id: DATA.CLIENT_ID,
            scope: 'scope1',
            redirect_uri: DATA.CLIENT_IMPLICIT_CALLBACK_URL,
            state: 'my-state'
        }), {
            validateStatus: (s) => true
        }).then(res => {
            chai.expect(res.status).to.equal(200);
            chai.expect(res.data.message).to.equal('success');
            chai.expect(res.data.tokens.error).to.be.undefined;
            chai.expect(res.data.tokens.access_token).to.be.a('string');
            chai.expect(res.data.tokens.token_type).to.equal('Bearer');
            chai.expect(res.data.tokens.expires_in).to.be.a('string');
            chai.expect(res.data.tokens.refresh_token).to.be.undefined;
            chai.expect(res.data.tokens.scope).to.equal('scope1');
            chai.expect(res.data.tokens.state).to.equal('my-state');
        });
    });

    it('Client Credentials', () => {
        return axios.post(DATA.AUTHORIZATION_URL + '/oauth/v2/token', buildQuery({
            grant_type: 'client_credentials',
            client_id: DATA.CLIENT_ID,
            client_secret: DATA.CLIENT_SECRET,
            scope: 'scope1'
        }), {
            validateStatus: (s) => true
        }).then(res => {
            chai.expect(res.status).to.equal(200);
            chai.expect(res.data.error).to.be.undefined;
            chai.expect(res.data.access_token).to.be.a('string');
            chai.expect(res.data.token_type).to.equal('Bearer');
            chai.expect(res.data.expires_in).to.be.a('number');
            chai.expect(res.data.refresh_token).to.be.undefined;
            chai.expect(res.data.scope).to.equal('scope1');
        });
    });

    let tokens;
    it('Resource Owner Credentials', () => {
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

    it('Refresh Token', () => {
        return axios.post(DATA.AUTHORIZATION_URL + '/oauth/v2/token',
            'grant_type=refresh_token'
            + `&client_id=${DATA.CLIENT_ID}`
            + `&client_secret=${DATA.CLIENT_SECRET}`
            + `&refresh_token=${tokens.refresh_token}`, {
                validateStatus: (s) => true
            }).then(res => {
            chai.expect(res.status).to.equal(200);
            chai.expect(res.data.token_type).to.equal('Bearer');
            chai.expect(res.data.scope).to.equal('scope1');
            chai.expect(res.data.access_token).to.be.a('string');
            chai.expect(res.data.refresh_token).to.be.a('string');
        });
    });
});