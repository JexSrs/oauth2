# Functions & Endpoints
The [`authorizationServer`](./authorization_server.md) provides some functions
that will be assigned to specific endpoints so your `front-end` application
and the clients can communicate with your authorization server.

## Authorize
The `authorize` function is used by your `front-end` application to allow a
user to authorize a client.
This function is assigned to the `authorize` endpoint.

### How to use
The `authorize` function **DOES NOT** authenticate the user's credentials, this part must
be implemented by other means.

So, you have to verify that your user is connected, than can be done by creating an
[`Express middleware`](http://expressjs.com/en/guide/using-middleware.html).
```javascript
function isLoggedIn(req, res, next) {
    if(verified) {
        req.user = 'user-id';
        next();
    } else {
        res.status(401).end('User is not logged in');
    }
}

app.get('/api/oauth/v2/authorize', isLoggedIn);
```

Then you have check if the user authorized the client and assign the user id as
described at the [`getUser`](./authorization_server.md#getuser) option:
```javascript
function isClientauthorized(req, res, next) {
    // You have to communicate with your front-end application
    if(req.query.state === 'rejected')
        req.user = null; // authorize function will handle the user's rejection.
    else {
        // req.user already have the user's id from
        // the isLoggedIn middleware. If not assign it here: req.user = 'user-id';
    }
    
    next();
}

app.get('/api/oauth/v2/authorize', isLoggedIn, isClientauthorized);
```

Finally, call the `authorize` function:
```javascript
app.get('/api/oauth/v2/authorize', isLoggedIn, isClientauthorized, authServer.authorize());
```

### Break down
The `authorize` function will follow the order below before reaching a registered flow:
* Verify that the query contains the keys `client_id`, `redirect_uri` and `response_type`.
* Execute [`validateRedirectURI`](./authorization_server.md#validateredirecturi) option.
* Execute [`isTemporarilyUnavailable`](./authorization_server.md#istemporarilyunavailable) option.
* Execute [`validateRequest`](./authorization_server.md#validaterequest) option.
* Execute [`validateScopes`](./authorization_server.md#validatescopes) option.
* Execute [`getUser`](./authorization_server.md#getuser) option.
* Match the `response_type` with a registered flow.
* Execute [`isFlowAllowed`](./authorization_server.md#isflowallowed) option.
* Execute [`issueRefreshTokenForThisClient`](./authorization_server.md#issuerefreshtokenforthisclient) option.
* Call the matched flow.


## Token
The `token` function is used by the clients to request a set of tokens.
This function is assigned to the `token` endpoint.

### How to use
The `token` function does not need to authorize the user and is called directly from the
client.
```javascript
app.get('/api/oauth/v2/token', authServer.token());
```

### Break down
The `token` function will follow the order below before reaching a registered flow:
* Verify that the query contains the key `grant_type`.
* Verify that [`getClientCredentials`](./authorization_server.md#getclientcredentials) option returned a client id.
* Execute [`validateClient`](./authorization_server.md#validateclient) option.
* Match the `grant_type` with a registered flow.
* Execute [`isFlowAllowed`](./authorization_server.md#isflowallowed) option.
* Execute [`issueRefreshTokenForThisClient`](./authorization_server.md#issuerefreshtokenforthisclient) option.
* Call the matched flow.

## Device Authorization
The `deviceAuthorization` function is used by clients that specifically want to use the
[`Device Authorization`](../flows/device_authorization.md) flow.
This function is assigned to the `deviceAuthorization` endpoint.

### How to use
The `deviceAuthorization` function does not need to authorize the user and is called directly from the
client.
```javascript
app.get('/api/oauth/v2/device_authorization', authServer.deviceAuthorization());
```

### Break down
The `deviceAuthorization` function will follow the same order as the [`token`](#token) function above.

## Introspection
The `introspection` function is assigned to the `introspection` endpoint
The `introspection` endpoint is used by the resource server to inquire if the token
sent by a client is valid.

### How to use
The `introspection` function is called directly.
```javascript
app.get('/api/oauth/v2/introspect', authServer.introspection());
```

### Break down
The `introspection` function will follow the order below:
* Get `client_id` and `client_secret` of the resource server using the [`getClientCredentials`](./authorization_server.md#getclientcredentials) option.
* Execute [`validateClient`](./authorization_server.md#validateclient) option.
* Verify if token is signed by this authorization server.
* Verify that the token is an access token.
* Execute the [`getAccessToken`](./authorization_server.md#getaccesstoken) option.
* Respond with the token status message.

## Revocation
The `revocation` function is assigned to the `revocation` endpoint
The `revocation` endpoint is used by the clients to revoke an access or refresh token.

### How to use
The `revocation` function is called directly.
```javascript
app.get('/api/oauth/v2/revoke', authServer.revocation());
```

### Break down
The `revocation` function will follow the order below:
* Get `client_id` and `client_secret` using the [`getClientCredentials`](./authorization_server.md#getclientcredentials) option.
* Execute [`validateClient`](./authorization_server.md#validateclient) option.
* Verify if token is signed by this authorization server.
* Verify that the token belongs to verified client.
* Call [`getAccessToken`](./authorization_server.md#getaccesstoken) or [`getRefreshToken`](./authorization_server.md#getrefreshtoken) option.
* Call the [`revoke`](./authorization_server.md#revoke) option.

## Authenticate
The `authenticate` function is used to authenticate a resource if the authorization server
and resource server are the same.
When we say the `authenicate` endpoint we refer to all the endpoints that are protected by
the `authenticate` function.

### How to use
The `authenticate` function will be used as a middleware:
```javascript
app.get('/protected', authServer.authenticate(), function (req, res) {
    // Authenticated
});
```

The `authenticate` function allows us to also check for specific scopes:
```javascript
// One scope
authServer.authenticate('scope1')

// Multiple scopes
authServer.authenticate(['scope1', 'scope2']);

// Multiple scopes but not all of them are necessary
authServer.authenticate(['scope1', 'scope2'], 'some');
```

### Break down
The `authenticate` function will follow the order below:
* Execute the [`getToken`](./authorization_server.md#gettoken) option
* Verify if token is signed by this authorization server.
* Verify that the token is an access token.
* Execute the [`getAccessToken`](./authorization_server.md#getaccesstoken) option.
* Check if the scopes are sufficient.
* Execute the [`setPayloadLocation`](./authorization_server.md#setpayloadlocation) option.
* Proceed to the next middleware.

## Metadata
The `metadata` function is assigned to the `metatdata` endpoint
The `metadata` endpoint is used by the clients to access information about
the authorization server such the authorization/token/revocation url.

### How to use
The `metadata` function is called directly.
```javascript
app.get('/api/oauth/v2/metadata', authServer.metadata());
```

### Break down
The `metadata` function will follow the order below:
* Create the metadata from [`metadata`](./authorization_server.md#metadata) option.