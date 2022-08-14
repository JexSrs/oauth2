const chai = require('chai');
const axios = require("axios");
const DATA = require("./data/data");
const express = require("express");
const buildQuery = require("../dist/utils/utils").buildQuery;
const {ResourceServer} = require('../dist');


let resServer = new ResourceServer({
    introspectionURL: DATA.AUTHORIZATION_URL + '/oauth/v2/introspection',
    audience: "me",
    body: {
        client_id: DATA.CLIENT_ID,
        client_secret: DATA.CLIENT_SECRET
    }
});

const rsExpress = express();
rsExpress.get('/protected', resServer.authenticate(), function (req, res) {
    res.status(200).end('protected-content');
});
rsExpress.get('/protected1', resServer.authenticate('scope1'), function (req, res) {
    res.status(200).end('protected-content');
});
rsExpress.get('/protected2', resServer.authenticate('scope2'), function (req, res) {
    res.status(200).end('protected-content');
});
rsExpress.get('/protected3', resServer.authenticate(['scope1', 'scope2'], 'all'), function (req, res) {
    res.status(200).end('protected-content');
});
rsExpress.get('/protected4', resServer.authenticate(['scope1', 'scope2'], 'some'), function (req, res) {
    res.status(200).end('protected-content');
});

const server = rsExpress.listen(DATA.CLIENT_RS_PORT, () => {
    console.log('Resource server listening at', DATA.CLIENT_RS_PORT);
});

setTimeout(server.close.bind(server), 60 * 1000);

describe("Introspection", function () {
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

    it('No scope', () => {
        return axios.get(DATA.CLIENT_RS_URL + '/protected', {
            headers: {
                Authorization: `Bearer ${tokens.access_token}`
            },
            validateStatus: (status) => true
        }).then(res => {
            chai.expect(res.status).to.equal(200);
            chai.expect(res.data).to.equal('protected-content');
        });
    });

    it('Valid scope (scope1)', () => {
        return axios.get(DATA.CLIENT_RS_URL + '/protected1', {
            headers: {
                Authorization: `Bearer ${tokens.access_token}`
            }
        }).then(res => {
            chai.expect(res.status).to.equal(200);
            chai.expect(res.data).to.equal('protected-content');
        });
    });

    it('Invalid scope (scope2)', () => {
        return axios.get(DATA.CLIENT_RS_URL + '/protected2', {
            headers: {
                Authorization: `Bearer ${tokens.access_token}`
            },
            validateStatus: (status) => true
        }).then(res => {
            chai.expect(res.status).to.equal(403);
            chai.expect(res.data.error).to.equal('insufficient_scope');
        });
    });

    it('Invalid scope (scope1 && scope2)', () => {
        return axios.get(DATA.CLIENT_RS_URL + '/protected3', {
            headers: {
                Authorization: `Bearer ${tokens.access_token}`
            },
            validateStatus: (status) => true
        }).then(res => {
            chai.expect(res.status).to.equal(403);
            chai.expect(res.data.error).to.equal('insufficient_scope');
        });
    });

    it('Valid scope (scope1 || scope2)', () => {
        return axios.get(DATA.CLIENT_RS_URL + '/protected4', {
            headers: {
                Authorization: `Bearer ${tokens.access_token}`
            },
            validateStatus: (status) => true
        }).then(res => {
            chai.expect(res.data).to.equal('protected-content');
        });
    });

    it('Request tokens (RT)', () => {
        return axios.post(DATA.AUTHORIZATION_URL + '/oauth/v2/token',
            'grant_type=refresh_token'
            + `&client_id=${DATA.CLIENT_ID}`
            + `&client_secret=${DATA.CLIENT_SECRET}`
            + `&refresh_token=${tokens.refresh_token}`, {}).then(res => {
            chai.expect(res.status).to.equal(200);
            chai.expect(res.data.token_type).to.equal('Bearer');
            chai.expect(res.data.scope).to.equal('scope1');
            chai.expect(res.data.access_token).to.be.a('string');
            chai.expect(res.data.refresh_token).to.be.a('string');
        });
    });

    it('Invalid tokens / No scope', () => {
        return axios.get(DATA.CLIENT_RS_URL + '/protected', {
            headers: {
                Authorization: `Bearer ${tokens.access_token}`
            },
            validateStatus: (status) => true
        }).then(res => {
            chai.expect(res.status).to.equal(401);
            chai.expect(res.data.error).to.equal('invalid_token');
        });
    });

    it('Invalid tokens / Valid scope (scope1)', () => {
        return axios.get(DATA.CLIENT_RS_URL + '/protected1', {
            headers: {
                Authorization: `Bearer ${tokens.access_token}`
            },
            validateStatus: (status) => true
        }).then(res => {
            chai.expect(res.status).to.equal(401);
            chai.expect(res.data.error).to.equal('invalid_token');
        });
    });

    it('Invalid tokens / Invalid scope (scope2)', () => {
        return axios.get(DATA.CLIENT_RS_URL + '/protected2', {
            headers: {
                Authorization: `Bearer ${tokens.access_token}`
            },
            validateStatus: (status) => true
        }).then(res => {
            chai.expect(res.status).to.equal(401);
            chai.expect(res.data.error).to.equal('invalid_token');
        });
    });

    it('Invalid tokens / Invalid scope (scope1 && scope2)', () => {
        return axios.get(DATA.CLIENT_RS_URL + '/protected3', {
            headers: {
                Authorization: `Bearer ${tokens.access_token}`
            },
            validateStatus: (status) => true
        }).then(res => {
            chai.expect(res.status).to.equal(401);
            chai.expect(res.data.error).to.equal('invalid_token');
        });
    });

    it('Invalid tokens / Valid scope (scope1 || scope2)', () => {
        return axios.get(DATA.CLIENT_RS_URL + '/protected4', {
            headers: {
                Authorization: `Bearer ${tokens.access_token}`
            },
            validateStatus: (status) => true
        }).then(res => {
            chai.expect(res.status).to.equal(401);
            chai.expect(res.data.error).to.equal('invalid_token');
        });
    });
});