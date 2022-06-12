const chai = require('chai');
const express = require('express');
const passport = require('./data/passport_data');
const DATA = require("./data/data");
const axios = require("axios");
const axiosCookieJarSupport = require('axios-cookiejar-support');
const tough = require('tough-cookie');

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

// Redirect to authorization server login page
clientExpress.get('/login', passport.authenticate('oauth2', {scope: ['scope1']}));
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

let servers = [
    clientExpress.listen(DATA.CLIENT_PORT, () => {
        console.log('Client server listening at', DATA.CLIENT_PORT);
    }),
];
setTimeout(() => servers.forEach(s => s.close()), 60 * 1000);


// TODO - https://www.passportjs.org/packages/passport-oauth2-client-password/
// TODO - https://www.passportjs.org/packages/passport-oauth2-resource-owner-password/

describe("Passport", function () {
    this.timeout(10 * 1000);

    axiosCookieJarSupport.wrapper(axios);
    const cookieJar = new tough.CookieJar();

    let tokens;
    it('Authorization code flow', () => {
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
});
