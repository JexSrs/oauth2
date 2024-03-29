const AUTHORIZATION_PORT = 4000;
const AUTHORIZATION_URL = `http://localhost:${AUTHORIZATION_PORT}`;
const ERROR_URI = `${AUTHORIZATION_URL}/docs/error_uri`;
const CLIENT_PORT = 4001;
const CLIENT_URL = `http://localhost:${CLIENT_PORT}`;
const CLIENT_CALLBACK_URL = `${CLIENT_URL}/authCode/callback`;
const CLIENT_ID = 'my-client-id';
const CLIENT_SECRET = 'my-secret';
const USERNAME = 'username';
const PASSWORD = 'password';

const CLIENT_IMPLICIT_PORT = 4002;
const CLIENT_IMPLICIT_URL = `http://localhost:${CLIENT_IMPLICIT_PORT}`;
const CLIENT_IMPLICIT_CALLBACK_URL = `${CLIENT_IMPLICIT_URL}/callback`;

const CLIENT_RS_PORT = 4003;
const CLIENT_RS_URL = `http://localhost:${CLIENT_RS_PORT}`;


module.exports = {
    AUTHORIZATION_PORT, AUTHORIZATION_URL, ERROR_URI,
    CLIENT_PORT, CLIENT_URL,
    CLIENT_CALLBACK_URL, CLIENT_ID, CLIENT_SECRET,
    USERNAME, PASSWORD,
    CLIENT_IMPLICIT_PORT, CLIENT_IMPLICIT_URL, CLIENT_IMPLICIT_CALLBACK_URL,
    CLIENT_RS_PORT, CLIENT_RS_URL
};