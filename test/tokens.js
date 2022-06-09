const {signToken, verifyToken} = require('../dist');
const chai = require("chai");

const PAYLOAD = {id: 5};
const SECRET = 'cat-secret';
const EXPIRES_IN = 5;

describe("Tokens", function () {
    it('JWT / payload verification', () => {
        let tokens = Array.from({length: 20}, (e, k) => signToken(PAYLOAD, SECRET, EXPIRES_IN));
        let validated = tokens.map(token => verifyToken(token, SECRET));
        validated.forEach(payload => {
            chai.expect(payload).to.be.an('object')
            chai.expect(payload.id).to.equal(5);
        });
    });

    it('JWT duplicity', () => {
        let tokens = Array.from({length: 20}, (e, k) => signToken(PAYLOAD, SECRET, EXPIRES_IN));
        for (let i = 1; i < tokens.length; i++)
            chai.expect(tokens[i - 1] === tokens[i]).to.equal(false);
    });
});