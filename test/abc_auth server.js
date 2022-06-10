const express = require('express');
const DATA = require("./data");
const {AuthorizationServer, implicit, clientCredentials, resourceOwnerCredentials, refreshToken, authorizationCode, Events} = require("../dist");

let authSrvDB = {};
let authCodeDB = {};

let authSrv = new AuthorizationServer({
    errorUri: DATA.AUTHORIZATION_ERROR_URI,
    accessTokenLifetime: 60, // 1 minute
    refreshTokenLifetime: 120, // 2 minutes
    secret: 'SUPER-DUPER-SECRET',
    isScopesValid: (scopes) => scopes.some(s => ['scope1', 'scope2'].includes(s)),
    getUser: req => req.loggedInUser,
    getAccessToken: data => {
        // console.log('GET ACCESS', authSrvDB.accessToken === data.accessToken)
        if(authSrvDB.accessToken === data.accessToken)
            return authSrvDB.accessToken;
        return null;
    },
    saveTokens: data => {
        // console.log('Saving tokens', data)
        authSrvDB = data;
        return true;
    },
    validateRedirectURI: (client_id, redirect_uri) =>
        client_id === DATA.CLIENT_ID
        && [DATA.CLIENT_CALLBACK_URL, DATA.CLIENT_IMPLICIT_CALLBACK_URL].includes(redirect_uri),
    isGrantTypeAllowed: (client_id, type) => true,
    isTemporaryUnavailable: req => false,
    validateUserAgent: (ua) => true,
    setPayloadLocation: (req, payload) => req.payload = payload,
    getClientCredentials: 'body'
});

authSrv.use(authorizationCode({
    usePKCE: true,
    allowCodeChallengeMethodPlain: false,
    authorizationCodeLifetime: 10, // 10 seconds
    deleteAuthorizationCode: data => {
        if(data.authorizationCode === authCodeDB.authorizationCode)
            authCodeDB = {};
        return true;
    },
    getAuthorizationCode: data => {
        if(authCodeDB.authorizationCode === data.authorizationCode)
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
        if(authSrvDB.refreshToken === data.refreshToken)
            authSrvDB = {};
        return true;
    },
    getRefreshToken: data => {
        if(authSrvDB.refreshToken === data.refreshToken)
            return authSrvDB.refreshToken;
        return null;
    }
}));

authSrv.on(Events.AUTHENTICATION_TOKEN_JWT_EXPIRED, req => {
    // console.log('jwt-expired');
});
authSrv.on(Events.AUTHENTICATION_TOKEN_DB_EXPIRED, req => {
    // console.log('db-expired');
});

// EXPRESS
const authorizationExpress = express();
authorizationExpress.use(express.urlencoded({type: "application/x-www-form-urlencoded", extended: true}));

authorizationExpress.get('/oauth/v2/authorize', function (req, res, next) {
    //console.log('AUTHORIZE:', req.query);
    // Verify user ...
    req.loggedInUser = `username`

    next();
}, authSrv.authorize());

authorizationExpress.post('/oauth/v2/token', function (req, res, next) {
    //console.log('TOKEN:', req.body, req.query);
    // console.log(req)
    next();
}, authSrv.token());

// No scope validation
authorizationExpress.get('/protected', authSrv.authenticate(), function (req, res) {
    res.status(200).end('protected-content');
});
// With valid scope
authorizationExpress.get('/protected1', authSrv.authenticate('scope1'), function (req, res) {
    res.status(200).end('protected-content');
});
// With invalid scope
authorizationExpress.get('/protected2', authSrv.authenticate('scope2'), function (req, res) {
    res.status(200).end('protected-content');
});


const server = authorizationExpress.listen(DATA.AUTHORIZATION_PORT, () => {
    console.log('Authorization server listening at', DATA.AUTHORIZATION_PORT);
});

setTimeout(server.close.bind(server), 60 * 1000);