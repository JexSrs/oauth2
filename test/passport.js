const chai = require('chai');
const express = require('express');
const passport = require('passport');
const OAuth2Strategy = require('passport-oauth2');
const {AuthorizationServer, authorizationCode, refreshToken, Events} = require('../dist');
const axios = require("axios");
const axiosCookieJarSupport = require('axios-cookiejar-support');
const tough = require('tough-cookie');

const DATA = new (function(){
    this.AUTHORIZATION_PORT = 3000;
    this.AUTHORIZATION_URL = `http://localhost:${this.AUTHORIZATION_PORT}`;
    this.AUTHORIZATION_ERROR_URI = `${this.AUTHORIZATION_URL}/docs/error_uri`;
    this.CLIENT_PORT = 3001;
    this.CLIENT_URL = `http://localhost:${this.CLIENT_PORT}`;
    this.CLIENT_CALLBACK_URL = `${this.CLIENT_URL}/auth/callback`;
    this.CLIENT_ID = 'my-client-id';
    this.CLIENT_SECRET = 'my-secret';
})();

let clientDB = {};
let authSrvDB = {};
let authCodeDB = {};

// Add passport strategy
const strategy = new OAuth2Strategy({
    authorizationURL: `${DATA.AUTHORIZATION_URL}/oauth/v2/authorize`,
    tokenURL: `${DATA.AUTHORIZATION_URL}/oauth/v2/token`,
    clientID: DATA.CLIENT_ID,
    clientSecret: DATA.CLIENT_SECRET,
    callbackURL: DATA.CLIENT_CALLBACK_URL,
    passReqToCallback: true,
    pkce: true,
    state: true,
}, function(req, accessToken, refreshToken, params, profile, cb) {
    //console.log('GOT NEW DATA:', {accessToken, refreshToken, params, profile});
    clientDB = {
        id: 'user-id',
        profile,
        accessToken, refreshToken
    };
    cb(undefined, {
        id: clientDB.id,
        profile: clientDB.profile,
        tokens: {
            accessToken,
            refreshToken
        }
    });
});
strategy.userProfile = function (accessToken, done) {
    // Request user profile here using access token
    done(null, {
        name: 'name',
        email: 'email'
    });
};
passport.use(strategy);
passport.serializeUser((user, done) => done(null, user));
passport.deserializeUser((obj, done) => done(null, obj));

// Create client server
const isLoggedIn = (req, res, next) => {
    if (req.user) next();
    else res.status(200).json({
        message: 'login-required'
    });
}

const clientExpress = express();
clientExpress.use(express.json({type: "**/**"}));
clientExpress.use(require('express-session')({ secret: 'keyboard cat', resave: true, saveUninitialized: true }));
clientExpress.use(passport.initialize());
clientExpress.use(passport.session());

clientExpress.get('/login', passport.authenticate('oauth2', {scope: ['scope1']})); // Redirect to authorization server login page
clientExpress.get('/auth/callback',
    function (req, res, next) {
        //console.log('CALLBACK:', req.query);
        next();
    },
    passport.authenticate('oauth2', {failureRedirect: '/failed'}),
    function (req, res) {
        // Successful authentication, redirect home.
        res.redirect('/success');
    });

clientExpress.get('/failed', (req, res) => res.status(200).json({
    message: 'failed-page'
}));
clientExpress.get('/success', (req, res) => res.status(200).json({
    message: 'success-page',
    user: req.user
}));

clientExpress.get('/secret', isLoggedIn, (req, res) =>{
    // console.log(req.user);
    res.send('secret-page');
});



// Configure authorization server
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
        client_id === DATA.CLIENT_ID && redirect_uri === DATA.CLIENT_CALLBACK_URL,
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

// Create Authorization (& resource) server
const authorizationExpress = express();
authorizationExpress.use(express.urlencoded({type: "application/x-www-form-urlencoded", extended: true}));
// authorizationExpress.use(express.json({type: "**/**"}));

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

authSrv.on(Events.AUTHENTICATION_TOKEN_JWT_EXPIRED, req => {
    // console.log('jwt-expired');
});
authSrv.on(Events.AUTHENTICATION_TOKEN_DB_EXPIRED, req => {
    // console.log('db-expired');
});


let servers = [
    authorizationExpress.listen(DATA.AUTHORIZATION_PORT, () => {
        console.log('Authorization server listening at', DATA.AUTHORIZATION_PORT);
    }),
    clientExpress.listen(DATA.CLIENT_PORT, () => {
        console.log('Client server listening at', DATA.CLIENT_PORT);
    }),
];
setTimeout(() => servers.forEach(s => s.close()), 60 * 1000);

/* Client tests at insomnia
    Request tokens: GET http://localhost:4000/login
    Client Server - Authenticate: GET http://localhost:4000/secret
    Authorization Server  - Authenticate: GET http://localhost:5000/protected{'' | '1' | '2'} (Will require bearer token auth)
*/

describe("Passport", function () {
    this.timeout(10 * 1000);

    axiosCookieJarSupport.wrapper(axios);
    const cookieJar = new tough.CookieJar();

    let tokens;
    it('Request tokens', () => {
        return axios.get(DATA.CLIENT_URL + '/login', {
            jar: cookieJar,
            withCredentials: true
        }).then(res => {
            let data = res.data;
            chai.expect(data.message).to.equal('success-page');
            chai.expect(data.user.id).to.equal('user-id');
            chai.expect(data.user.profile.name).to.equal('name');
            chai.expect(data.user.profile.email).to.equal('email');
            tokens = data.user.tokens;
        });
    });

    it('Authorization server (no scope)', () => {
        return axios.get(DATA.AUTHORIZATION_URL + '/protected', {
            headers: {
                Authorization: `Bearer ${tokens.accessToken}`
            }
        }).then(res => {
            chai.expect(res.data).to.equal('protected-content');
        });
    });

    it('Authorization server (scope1)', () => {
        return axios.get(DATA.AUTHORIZATION_URL + '/protected1', {
            headers: {
                Authorization: `Bearer ${tokens.accessToken}`
            }
        }).then(res => {
            chai.expect(res.data).to.equal('protected-content');
        });
    });

    it('Authorization server (scope2)', () => {
        return axios.get(DATA.AUTHORIZATION_URL + '/protected2', {
            headers: {
                Authorization: `Bearer ${tokens.accessToken}`
            },
            validateStatus: (status) => true
        }).then(res => {
            chai.expect(res.status).to.equal(403);
        });
    });

    it('Refresh token', () => {
        return axios.post(DATA.AUTHORIZATION_URL + '/oauth/v2/token',
            'grant_type=refresh_token'
            + `&client_id=${DATA.CLIENT_ID}`
            + `&client_secret=${DATA.CLIENT_SECRET}`
            + `&refresh_token=${tokens.refreshToken}`, {
        }).then(res => {
            chai.expect(res.status).to.equal(200);
            chai.expect(res.data.token_type).to.equal('Bearer');
            chai.expect(res.data.scope).to.equal('scope1');
            chai.expect(res.data.access_token).to.be.a('string');
            chai.expect(res.data.refresh_token).to.be.a('string');
        });
    });

    it('Authorization server (no scope) old tokens', () => {
        return axios.get(DATA.AUTHORIZATION_URL + '/protected', {
            headers: {
                Authorization: `Bearer ${tokens.accessToken}`
            },
            validateStatus: (status) => true
        }).then(res => {
            chai.expect(res.status).to.equal(401);
            chai.expect(res.data.error).to.equal('invalid_token');
        });
    });
});
