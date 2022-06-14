const express = require('express');
const DATA = require("./data/data");
const {
    AuthorizationServer,
    implicit,
    clientCredentials,
    resourceOwnerCredentials,
    refreshToken,
    authorizationCode,
    deviceFlow,
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
    saveTokens: (data, req) => {
        // console.log('Saving tokens', data)
        authSrvDB = data;
        return true;
    },
    validateRedirectURI: (client_id, redirect_uri) =>
        client_id === DATA.CLIENT_ID
        && [DATA.CLIENT_CALLBACK_URL, DATA.CLIENT_IMPLICIT_CALLBACK_URL].includes(redirect_uri),
    isImplementationAllowed: (client_id, type) => true,
    isTemporaryUnavailable: req => false,
    validateRequest: (req) => true,
    setPayloadLocation: (req, payload) => req.payload = payload,
    getClientCredentials: 'body'
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
    },
    validateClient: (client_id, client_secret) =>
        client_id === DATA.CLIENT_ID && client_secret === DATA.CLIENT_SECRET,
}));
authSrv.use(implicit());
authSrv.use(clientCredentials({
    validateClient: (client_id, client_secret) =>
        client_id === DATA.CLIENT_ID && client_secret === DATA.CLIENT_SECRET
}));
authSrv.use(resourceOwnerCredentials({
    validateClient: (client_id, client_secret) =>
        client_id === DATA.CLIENT_ID && client_secret === DATA.CLIENT_SECRET,
    validateUser: (username, password) =>
        username === DATA.USERNAME && password === DATA.PASSWORD,
}));
authSrv.use(refreshToken({
    validateClient: (client_id, client_secret) =>
        client_id === DATA.CLIENT_ID && client_secret === DATA.CLIENT_SECRET,
    deleteTokens: data => {
        // console.log('DELETING', authSrvDB.refreshToken === data.refreshToken)
        if (authSrvDB.refreshToken === data.refreshToken)
            authSrvDB = {};
        return true;
    },
    getRefreshToken: data => {
        if (authSrvDB.refreshToken === data.refreshToken)
            return authSrvDB.refreshToken;
        return null;
    }
}));
authSrv.use(deviceFlow({
    expiresIn: 60,
    interval: 3,
    verificationURI: 'https://example.com/device',
    validateClient: client_id => client_id === DATA.CLIENT_ID,
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


authSrv.on(Events.AUTHENTICATION_TOKEN_JWT_EXPIRED, req => {
    // console.log('jwt-expired');
});
authSrv.on(Events.AUTHENTICATION_TOKEN_DB_EXPIRED, req => {
    // console.log('db-expired');
});
authSrv.on(Events.TOKEN_FLOWS_DEVICE_CODE_PENDING, req => {
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
    req.loggedInUser = `username`

    next();
}, authSrv.authorize());

authorizationExpress.post('/oauth/v2/token', function (req, res, next) {
    // console.log('TOKEN:', req.body, req.query);
    // console.log(req)
    next();
}, authSrv.token());

authorizationExpress.post('/oauth/v2/device', function (req, res, next) {
    //console.log('TOKEN:', req.body, req.query);
    // console.log(req)
    next();
}, authSrv.device());

authorizationExpress.post('/oauth/v2/introspection', function (req, res, next) {
    //console.log('TOKEN:', req.body, req.query);
    // console.log(req)
    next();
}, authSrv.introspection());

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