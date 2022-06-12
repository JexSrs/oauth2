const {signToken, verifyToken} = require('../dist');
const {randStr} = require('../dist/modules/utils');
const chai = require("chai");

const PAYLOAD = {id: 5};
const SECRET = randStr(Math.floor(Math.random() * (128 - 32) + 32));
const EXPIRES_IN = 5;

describe("Tokens", function () {
    it('JWT / payload verification', () => {
        let tokens = Array.from({length: 50}, (e, k) => signToken(PAYLOAD, SECRET, EXPIRES_IN));
        let validated = tokens.map(token => verifyToken(token, SECRET));
        validated.forEach(payload => {
            chai.expect(payload).to.be.an('object')
            chai.expect(payload.id).to.equal(5);
        });
    });

    it('JWT duplicity', () => {
        let tokens = Array.from({length: 400}, (e, k) => signToken(PAYLOAD, SECRET, EXPIRES_IN));
        tokens.forEach(token => chai.expect(tokens.filter(t => t === token).length).to.equal(1));
    });
});