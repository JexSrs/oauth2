const chai = require('chai');
chai.use(require("chai-as-promised"));
const expect = chai.expect;

const {Client, Server} = require('../dist');
const express = require('express');

const app = express();
app.use(express.text());

app.get('/', function (req, res) {

});

let server = app.listen(3000);
const client = new Client({});


describe('With Encryption', function () {
    it('GET (encrypt)', async () => {

    });
});


setTimeout(() => server.close(), 5000);
