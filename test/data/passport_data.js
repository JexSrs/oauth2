const passport = require('passport');
const OAuth2Strategy = require('passport-oauth2');

const DATA = require("./data");

let clientDB = {};

// Authorization code strategy
const authCodeStrategy = new OAuth2Strategy({
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

authCodeStrategy.userProfile = function (accessToken, done) {

    // Request user profile here using access token
    done(null, {
        name: 'name',
        email: 'email'
    });
};





passport.use(authCodeStrategy);
passport.serializeUser((user, done) => done(null, user));
passport.deserializeUser((obj, done) => done(null, obj));


module.exports = passport;