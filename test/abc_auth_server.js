const express = require('express');
const DATA = require("./data/data");
const {
    AuthorizationServer,
    implicit,
    clientCredentials,
    resourceOwnerCredentials,
    refreshToken,
    authorizationCode,
    deviceAuthorization,
    Events
} = require("../dist");

let authSrvDB = {};
let authCodeDB = {};
let bucketDB = {};
let deviceDB = {};
let devicePendingRequestCounter = 0;

let authSrv = new AuthorizationServer({
    errorUri: DATA.ERROR_URI,
    accessTokenLifetime: 60, // 1 minute
    refreshTokenLifetime: 120, // 2 minutes
    secret: 'SUPER-DUPER-SECRET',
    validateScopes: (scopes) => scopes.some(s => ['scope1', 'scope2'].includes(s)),
    getUser: req => req.loggedInUser,
    getAccessToken: data => {
        // console.log('GET ACCESS', authSrvDB.accessToken === data.accessToken)
        if (authSrvDB.accessToken === data.accessToken)
            return authSrvDB.accessToken;
        return null;
    },
    getRefreshToken: data => {
        if (authSrvDB.refreshToken === data.refreshToken)
            return authSrvDB.refreshToken;
        return null;
    },
    saveTokens: (data, req) => {
        // console.log('Saving tokens', data)
        authSrvDB = data;
        return true;
    },
    validateRedirectURI: (client_id, redirect_uri) =>
        client_id === DATA.CLIENT_ID
        && [DATA.CLIENT_CALLBACK_URL, DATA.CLIENT_IMPLICIT_CALLBACK_URL].includes(redirect_uri),
    isFlowAllowed: (client_id, type, req) => true,
    isTemporarilyUnavailable: req => false,
    validateRequest: (req) => true,
    setPayloadLocation: (req, payload) => req.payload = payload,
    getClientCredentials: 'body',
    issuer: 'me',
    validateClient: (client_id, client_secret) =>
        client_id === DATA.CLIENT_ID && (client_secret === undefined ? true : client_secret === DATA.CLIENT_SECRET),
    revoke: (data, req) => {
        if(data.what === 'access_token')
            authSrvDB.accessToken = '';
        else if(data.what === 'refresh_token')
            authSrvDB.refreshToken = '';
        else if(data.what === 'record') {
            if (authSrvDB.refreshToken === data.refreshToken)
                authSrvDB = {};
        }

        return true;
    }
});

authSrv.use(authorizationCode({
    usePKCE: true,
    allowCodeChallengeMethodPlain: false,
    authorizationCodeLifetime: 10, // 10 seconds
    deleteAuthorizationCode: data => {
        if (data.authorizationCode === authCodeDB.authorizationCode)
            authCodeDB = {};
        return true;
    },
    getAuthorizationCode: data => {
        if (authCodeDB.authorizationCode === data.authorizationCode)
            return authCodeDB;
        return null;
    },
    saveAuthorizationCode: data => {
        authCodeDB = data;
        return true;
    }
}));
authSrv.use(implicit());
authSrv.use(clientCredentials());
authSrv.use(resourceOwnerCredentials({
    validateUser: (username, password) =>
        username === DATA.USERNAME && password === DATA.PASSWORD,
}));
authSrv.use(refreshToken());
authSrv.use(deviceAuthorization({
    expiresIn: 60,
    interval: 3,
    verificationURI: 'https://example.com/device',
    getUser: (deviceCode, userCode) => {
        return {id: 'user-id'};
    },
    saveBucket: (deviceCode, bucket, expiresIn) => {
        bucketDB = {deviceCode, bucket, expiresIn};
        return true;
    },
    getBucket: deviceCode => {
        if (deviceCode === bucketDB.deviceCode)
            return bucketDB.bucket;
        return null;
    },
    saveDevice: data => {
        deviceDB = data;
        return true;
    },
    getDevice: data => {
        if (data.deviceCode === deviceDB.deviceCode)
            return deviceDB;
        return null;
    },
    removeDevice: data => {
        if (data.deviceCode === deviceDB.deviceCode)
            deviceDB = {};
        return true;
    }
}));


authSrv.on(Events.AUTHENTICATION_INVALID_TOKEN_JWT, req => {
    // console.log('jwt-expired');
});
authSrv.on(Events.AUTHENTICATION_INVALID_TOKEN_DB, req => {
    // console.log('db-expired');
});
authSrv.on(Events.REQUEST_PENDING, req => {
    devicePendingRequestCounter++;
    if (devicePendingRequestCounter === 2)
        deviceDB.status = 'completed';
});

// EXPRESS
const authorizationExpress = express();
authorizationExpress.use(express.urlencoded({type: "application/x-www-form-urlencoded", extended: true}));
authorizationExpress.use(express.json({type: "application/json"}));

authorizationExpress.get('/oauth/v2/authorize', function (req, res, next) {
    //console.log('AUTHORIZE:', req.query);
    // Verify user ...
    req.loggedInUser = "username"

    next();
}, authSrv.authorize());

authorizationExpress.post('/oauth/v2/token', function (req, res, next) {
    // console.log('TOKEN:', req.body, req.query);
    // console.log(req)
    next();
}, authSrv.token());

authorizationExpress.post('/oauth/v2/device_authorization', function (req, res, next) {
    //console.log('device:', req.body, req.query);
    // console.log(req)
    next();
}, authSrv.deviceAuthorization());

authorizationExpress.post('/oauth/v2/introspection', function (req, res, next) {
    //console.log('introspection:', req.body, req.query);
    // console.log(req)
    next();
}, authSrv.introspection());

authorizationExpress.post('/oauth/v2/revocation', function (req, res, next) {
    //console.log('revocation:', req.body, req.query);
    // console.log(req)
    next();
}, authSrv.revocation());

authorizationExpress.get('/protected', authSrv.authenticate(), function (req, res) {
    res.status(200).end('protected-content');
});
authorizationExpress.get('/protected1', authSrv.authenticate('scope1'), function (req, res) {
    res.status(200).end('protected-content');
});
authorizationExpress.get('/protected2', authSrv.authenticate('scope2'), function (req, res) {
    res.status(200).end('protected-content');
});
authorizationExpress.get('/protected3', authSrv.authenticate(['scope1', 'scope2'], 'all'), function (req, res) {
    res.status(200).end('protected-content');
});
authorizationExpress.get('/protected4', authSrv.authenticate(['scope1', 'scope2'], 'some'), function (req, res) {
    res.status(200).end('protected-content');
});


const server = authorizationExpress.listen(DATA.AUTHORIZATION_PORT, () => {
    console.log('Authorization server listening at', DATA.AUTHORIZATION_PORT);
});

setTimeout(server.close.bind(server), 60 * 1000);