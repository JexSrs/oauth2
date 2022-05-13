const chai = require('chai');
chai.use(require("chai-as-promised"));
const expect = chai.expect;

const {Client, Server} = require('../dist');
const express = require('express');

const CLIENT_ADDRESS = 'http://localhost:3000';
const SERVER_PUBLIC_KEY = '-----BEGIN PUBLIC KEY-----\n' +
    'MIIBITANBgkqhkiG9w0BAQEFAAOCAQ4AMIIBCQKCAQBJOG67Po/8/Px3NaQf9ar/\n' +
    'oqNTvRacXo6oanSJrbOq0a+VNikAW/e07hWlXUfa4ppRnMN+gXWQwZS7aIyURiBf\n' +
    '+h2h9Zqmbl9YIpvgve+tMZbcOxPdYTSuu2Juxxt4SA4FzqWeAhPfWEIhBtTEUKTL\n' +
    'ByOpl/uPPr5rwCWEZNWmqMuxdf6fRt4WK0GZa+HViNXXFJz6cdBaOkSQMZOTsXS9\n' +
    'aOM6lftlCcEg9/leMCNP18LzzHausYf7RQLmycxgS6Sn28DXukMpGDSZaalCy355\n' +
    'MQq7KaLUbNzq+y5B4lDjzPcPal+UzXcmVxVXwt8ebQkTVue1M0feBQ0iNJf1OCdL\n' +
    'AgMBAAE=\n' +
    '-----END PUBLIC KEY-----';
const SERVER_PRIVATE_KEY = '-----BEGIN RSA PRIVATE KEY-----\n' +
    'MIIEoQIBAAKCAQBJOG67Po/8/Px3NaQf9ar/oqNTvRacXo6oanSJrbOq0a+VNikA\n' +
    'W/e07hWlXUfa4ppRnMN+gXWQwZS7aIyURiBf+h2h9Zqmbl9YIpvgve+tMZbcOxPd\n' +
    'YTSuu2Juxxt4SA4FzqWeAhPfWEIhBtTEUKTLByOpl/uPPr5rwCWEZNWmqMuxdf6f\n' +
    'Rt4WK0GZa+HViNXXFJz6cdBaOkSQMZOTsXS9aOM6lftlCcEg9/leMCNP18LzzHau\n' +
    'sYf7RQLmycxgS6Sn28DXukMpGDSZaalCy355MQq7KaLUbNzq+y5B4lDjzPcPal+U\n' +
    'zXcmVxVXwt8ebQkTVue1M0feBQ0iNJf1OCdLAgMBAAECggEAETF0Jvm42+IX8nIh\n' +
    'GPQZ9C8fhQFItu0pOHjO5qloH/te7H2sQQ5Xax/g61StE8PUEsfpy+HgVl5ua1dQ\n' +
    'c1zIK2FS5f4DE4OlVc/CpJJVHmkfkJU6w+gYc9NCeNq+I49f45Mzppe8TNyvoou1\n' +
    'GGgLWjVR9XfftTI5ipmy9ZSr6pdF+H3OKK4YxyH4axkfAVFbHDW85qRvz9CWY5Re\n' +
    'QFbSiiiavKU6ADs6TIV0wXwsS8pxamt2FflayKajYAnANG/CVxqrKsIw01VWdGmK\n' +
    'dF4cWWF3KbFtKtBe8Ofk4VBcQkyBfBjt5sEL8AT7qp7T52r4SHuADrhUYSjVrMuF\n' +
    'YP23WQKBgQCKIRB2UpPttyg0F2/t8oatFSHVN0yNYc+FrXhsnzMbX8OBBwDMgpYU\n' +
    'f/ultAkouSryR/dwNRZ4+FX8YKhbKyr52eJiGZTl+VtsUI3yN7oyYWIrE+WwW+YD\n' +
    'X8mSlgHF/775NWaT6j1BxEy+TzV0Rg5c3QPcezN1nH7HHeg51b8shQKBgQCHs8RT\n' +
    'cPnp+rjd8kekMlHAdjXm2OYbSoWf9TnHX6xdPfyan8dxs2dONhdwC56SyQBFUedq\n' +
    'XM2AMppzjovFT/G56WOMZkGEjayMxI7hA/i3DK6kYRrPe5yppW4p+4oUXssjWqX9\n' +
    'RyKe3bVORfHm+TF6zEc5TXTD+YpJDPIEyHf1jwKBgHaqPShJfQhlp0ZJNEFpb0XW\n' +
    't8Aix8NWWh/vjVtT0WYc+SopyAfpz+FAqgILDytLGJgYN3zQPsQiJEyzBS99gGgx\n' +
    'RQkeDQsdE+uTsL58HZwWiW2UpGjEKnCPo+4orNFbCsexlrRQMdwENiHwjm2bmc8x\n' +
    'mJWbyfOqREfva4f0F065AoGAOgRGVHJBtqIltWYm8PE+eG1RoC9tOY/Dz151ZGLn\n' +
    '+zlMLQNQrrDH4u1HWfTtx829muVobdXdWgjIdc0kvqfuLdC1acoyCqzTb599goBD\n' +
    'Lmdypv6JCtnLYdBDaBmNsCXS7XuM6dsm1wrsv9kxkdFKMTjy3nHaEQs37wFk21yl\n' +
    'xMsCgYBgxtBNQ38eYTqEajJL63wPuyA2TAJUcYN1TWj3Z668ncl4hI1uSCVA1yWa\n' +
    'YHRPV2LuXZXKU7P2ECa34us8myWL7V8pvKrlex1vzYko0D+z1NztmoswoLvyPOxP\n' +
    'tRAmKQJMi3FMWlrnfvV0klSDZAV2fUyQJH1OxtRZWaZxUh4glQ==\n' +
    '-----END RSA PRIVATE KEY-----';

let commServer = new Server({
    privateKey: SERVER_PRIVATE_KEY,
    fingerPrinter: (req) => "fingerprint",
    timeout: 1000,
    logErrors: true
});

const app = express();
app.use(express.text());

app.get('/plain', function (req, res) {
    Server.send(res, {
        data: false,
    });
});

app.delete('/plain', function (req, res) {
    Server.send(res, {
        data: false,
    });
});

app.post('/plain', function (req, res) {
    Server.send(res, {
        data: {
            hasData: !!req.body,
            validData: req.body === 'test-post'
        }
    });
});

app.patch('/plain', (req, res) => {
    Server.send(res, {
        data: {
            hasData: !!req.body,
            validData: req.body === 'test-patch'
        }
    });
});

app.put('/plain', (req, res) => {
    Server.send(res, {
        data: {
            hasData: !!req.body,
            validData: req.body === 'test-put'
        }
    });
});

app.get('/', commServer.encrypt(), function (req, res) {
    res.sendEnc({
        data: !!req.data,
    });
});

app.delete('/', commServer.encrypt(), function (req, res) {
    res.sendEnc({
        data: !!req.data,
    });
});

app.post('/', commServer.encrypt(), function (req, res) {
    res.sendEnc({
        data: {
            hasData: !!req.data,
            validData: req.data === 'test-post'
        },
    });
});

app.patch('/', commServer.encrypt(), (req, res) => {
    res.sendEnc({
        data: {
            hasData: !!req.data,
            validData: req.data === 'test-patch'
        },
    });
});

app.put('/', commServer.encrypt(), (req, res) => {
    res.sendEnc({
        data: {
            hasData: !!req.data,
            validData: req.data === 'test-put'
        },
    });
});

let server = app.listen(3000);
const client = new Client({
    serverPublicKey: SERVER_PUBLIC_KEY,
    serverPublicKeyBits: 2048,
    useInterceptors: false
});

describe('Without encryption', function () {
    it('GET (encrypt)', async () => {
        try {
            await client.get(CLIENT_ADDRESS + '/plain', {
                timeout: 2000,
            });
            throw new Error('Did not throw')
        } catch (e) {
        }
    });

    it('DELETE (encrypt)', async () => {
        try {
            await client.delete(CLIENT_ADDRESS + '/plain', {
                timeout: 2000,
            });
            throw new Error('Did not throw')
        } catch (e) {
        }
    });

    it('POST (encrypt)', async () => {
        try {
            await client.post(CLIENT_ADDRESS + '/plain', 'test-post', {
                timeout: 2000,
            });
            throw new Error('Did not throw')
        } catch (e) {
        }
    });

    it('PATCH (encrypt)', async () => {
        try {
            await client.patch(CLIENT_ADDRESS + '/plain', 'test-patch', {
                timeout: 2000,
            });
            throw new Error('Did not throw')
        } catch (e) {
        }
    });

    it('PUT (encrypt)', async () => {
        try {
            await client.put(CLIENT_ADDRESS + '/plain', 'test-put', {
                timeout: 2000,
            });
            throw new Error('Did not throw')
        } catch (e) {
        }
    });

    it('GET (plain)', async () => {
        let res = await client.axios.get(CLIENT_ADDRESS + '/plain', {
            timeout: 2000,
        });

        expect(res.status).to.equal(200);
        expect(res.data).to.false;
    });

    it('DELETE (plain)', async () => {
        let res = await client.axios.delete(CLIENT_ADDRESS + '/plain', {
            timeout: 2000,
        });

        expect(res.status).to.equal(200);
        expect(res.data).to.false;
    });

    it('POST (plain)', async () => {
        let res = await client.axios.post(CLIENT_ADDRESS + '/plain', 'test-post', {
            timeout: 2000,
            headers: {
                'content-type': 'text/plain'
            }
        });

        expect(res.status).to.equal(200);
        expect(res.data.hasData).to.true;
        expect(res.data.validData).to.true;
    });

    it('PATCH (plain)', async () => {
        let res = await client.axios.patch(CLIENT_ADDRESS + '/plain', 'test-patch', {
            timeout: 2000,
            headers: {
                'content-type': 'text/plain'
            }
        });

        expect(res.status).to.equal(200);
        expect(res.data.hasData).to.true;
        expect(res.data.validData).to.true;
    });

    it('PUT (plain)', async () => {
        let res = await client.axios.put(CLIENT_ADDRESS + '/plain', 'test-put', {
            timeout: 2000,
            headers: {
                'content-type': 'text/plain'
            }
        });

        expect(res.status).to.equal(200);
        expect(res.data.hasData).to.true;
        expect(res.data.validData).to.true;
    });
});

describe('With Encryption', function () {
    it('GET (encrypt)', async () => {
        let res = await client.get(CLIENT_ADDRESS, {
            timeout: 2000,
        });

        expect(res.status).to.equal(200);
        expect(res.data).to.false;
    });

    it('DELETE (encrypt)', async () => {
        let res = await client.delete(CLIENT_ADDRESS, {
            timeout: 2000,
        });

        expect(res.status).to.equal(200);
        expect(res.data).to.false;
    });

    it('POST (encrypt)', async () => {
        let res = await client.post(CLIENT_ADDRESS, 'test-post', {
            timeout: 2000,
        });

        expect(res.status).to.equal(200);
        expect(res.data.hasData).to.true;
        expect(res.data.validData).to.true;
    });

    it('PATCH (encrypt)', async () => {
        let res = await client.patch(CLIENT_ADDRESS, 'test-patch', {
            timeout: 2000,
        });

        expect(res.status).to.equal(200);
        expect(res.data.hasData).to.true;
        expect(res.data.validData).to.true;
    });

    it('PUT (encrypt)', async () => {
        let res = await client.put(CLIENT_ADDRESS, 'test-put', {
            timeout: 2000,
        });

        expect(res.status).to.equal(200);
        expect(res.data.hasData).to.true;
        expect(res.data.validData).to.true;
    });

    it('GET (plain)', async () => {
        try {
            await client.axios.get(CLIENT_ADDRESS, {
                timeout: 2000,
            });
            throw new Error('Did not throw')
        } catch (e) {
        }
    });

    it('DELETE (plain)', async () => {
        try {
            await client.axios.delete(CLIENT_ADDRESS, {
                timeout: 2000,
            });
            throw new Error('Did not throw')
        } catch (e) {
        }
    });

    it('POST (plain)', async () => {
        try {
            await client.axios.post(CLIENT_ADDRESS, 'test-post', {
                timeout: 2000,
            });
            throw new Error('Did not throw')
        } catch (e) {
        }
    });

    it('PATCH (plain)', async () => {
        try {
            await client.axios.patch(CLIENT_ADDRESS, 'test-patch', {
                timeout: 2000,
            });
            throw new Error('Did not throw')
        } catch (e) {
        }
    });

    it('PUT (plain)', async () => {
        try {
            await client.axios.put(CLIENT_ADDRESS, 'test-put', {
                timeout: 2000,
            });
            throw new Error('Did not throw')
        } catch (e) {
        }
    });
});


setTimeout(() => server.close(), 8000);
