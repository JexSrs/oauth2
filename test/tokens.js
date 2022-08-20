const {signToken, verifyToken} = require('../dist');
const {randStr} = require('../dist/utils/general.utils');
const chai = require("chai");

const PAYLOAD = {
    id: 5,
    key: undefined,
    key2: null
};
const SECRET = randStr(Math.floor(Math.random() * (128 - 32) + 32));
const EXPIRES_IN = 5;
const ISSUER = "custom-issuer";

describe("Tokens", function () {
    it('JWT / payload verification', () => {
        let tokens = Array.from({length: 50}, (e, k) => signToken({
            payload: PAYLOAD,
            secret: SECRET,
            expiresIn: EXPIRES_IN,
            issuer: ISSUER,
            audience: ISSUER
        }));
        let validated = tokens.map(token => verifyToken(token, SECRET, ISSUER, ISSUER));
        validated.forEach(payload => {
            chai.expect(payload).to.be.an('object')
            chai.expect(payload.id).to.equal(5);
            chai.expect(payload.hasOwnProperty('key')).to.be.false;
            chai.expect(payload.key2).to.be.null;
        });
    });

    it('JWT duplicity', () => {
        let tokens = Array.from({length: 400}, (e, k) => signToken({
            payload: PAYLOAD,
            secret: SECRET,
            expiresIn: EXPIRES_IN,
            issuer: ISSUER,
            audience: ISSUER
        }));
        tokens.forEach(token => chai.expect(tokens.filter(t => t === token).length).to.equal(1));
    });
});