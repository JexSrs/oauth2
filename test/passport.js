const express = require('express');
const passport = require('passport');
const OAuth2Strategy = require('passport-oauth2');
const {AuthorizationServer, authorizationCode, Events} = require('../dist');

const DATA = new (function(){
    this.AUTHORIZATION_PORT = 5000;
    this.AUTHORIZATION_URL = `http://localhost:${this.AUTHORIZATION_PORT}`;
    this.AUTHORIZATION_ERROR_URI = `${this.AUTHORIZATION_URL}/docs/error_uri`;
    this.CLIENT_PORT = 4000;
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
    console.log('GOT NEW DATA:', {accessToken, refreshToken, params, profile});
    clientDB = {
        id: 'user-id',
        profile, params,
        accessToken, refreshToken
    };
    cb(undefined, {
        id: clientDB.id,
        profile: clientDB.profile
    });
});
strategy.userProfile = function (accessToken, done) {
    console.log('USER_PROFILE:', accessToken);
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
    console.log(req.user);
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
        if(authSrvDB.accessToken === data.accessToken)
            return authSrvDB.accessToken;
        return null;
    },
    saveTokens: data => {
        authSrvDB = data;
        return true;
    },
    validateRedirectURI: (client_id, redirect_uri) =>
        client_id === DATA.CLIENT_ID && redirect_uri === DATA.CLIENT_CALLBACK_URL,
    isGrantTypeAllowed: (client_id, type) => true,
    isTemporaryUnavailable: req => false,
    rejectEmbeddedWebViews: false,
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

// Create Authorization (& resource) server
const authorizationExpress = express();
authorizationExpress.use(express.urlencoded({type: "application/x-www-form-urlencoded", extended: true}));
// authorizationExpress.use(express.json({type: "**/**"}));

authorizationExpress.get('/oauth/v2/authorize', function (req, res, next) {
    console.log('AUTHORIZE:', req.query);
    // Verify user ...
    req.loggedInUser = `username`

    next();
}, authSrv.authorize());

authorizationExpress.post('/oauth/v2/token', function (req, res, next) {
    console.log('TOKEN:', req.body, req.query);
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
    console.log('jwt-expired')
});

authSrv.on(Events.AUTHENTICATION_TOKEN_DB_EXPIRED, req => {
    console.log('db-expired')
});






// describe('With Encryption', function () {
//     it('GET (encrypt)', async () => {
//
//     });
// });


let servers = [
    authorizationExpress.listen(DATA.AUTHORIZATION_PORT, () => {
        console.log('Authorization server listening at', DATA.AUTHORIZATION_PORT);
    }),
    clientExpress.listen(DATA.CLIENT_PORT, () => {
        console.log('Client server listening at', DATA.CLIENT_PORT);
    }),
];
// setTimeout(() => servers.forEach(s => s.close()), 60 * 1000);
