# Authorization Server
The authorization server is what the user interacts with when an application is requesting
access to their account. This is the server that displays the OAuth prompt, and where the user
approves or denies the application’s request. The authorization server is also responsible
for granting access tokens after the user authorizes the application.

The `oauth2` library provides you with logic behind the `front-end`. Meaning after the user
authorizes a request the `AuthorizationServer` is responsible to generate and grant access tokens.

## How to use
First create an instance of the authorization server:
```javascript
import {AuthorizationServer} from "oauth2";

const authServer = new AuthorizationServer({/* options */});
```
After that you have to implement the desired flow. In this example we will use the
[`Authorization Code`](../flows/authorization_code.md) flow:
```javascript
import {authorizationCode} from "oauth2";

authServer.use(authorizationCode({/* options */}));
```
And finally expose the necessary [`functions`](functions_and_endpoints.md) to your `Express` server:
```javascript
app.get('/oauth/v2/authorize', isLoggedIn, authServer.authorize());
app.post('/oauth/v2/token', authServer.token());
```

## Options
The `AuthorizationServer` options are either options needed by the `AuthorizationServer` instance
itself or common options used by all the OAuth2 flows.

### `getToken`
Used by the [`authenticate`](functions_and_endpoints.md#authenticate) function to inquire about the
location of the access token. It defaults to the authorization header:

```javascript
getToken: req => req.headers['authorization']?.split(' ')?.[1];
```

In the example above the authorization header will look like: `Bearer <token>`.
Make note that you have to return the `<token>` part only.

### `setPayloadLocation`
Used by the [`authenticate`](functions_and_endpoints.md#authenticate) function to inquire about the
where to save the `payload` if the authentication succeeds. It defaults to `req.payload`:

```javascript
setPayloadLocation: (req, payload) => req.payload = payload;
```

### `accessTokenLifetime`
The time in seconds where the access token will be valid. It defaults to `86400 sec` = 1 day.

In case you want an access token to never expire you can set this field to `null`.
Although it is not recommended, if you still want to never expire an access token,
take note of the following:
* The access will not have an expiration date. Meaning the JWT expiration check will always pass.
* Refresh tokens **will be** generated if you include the [`refreshToken`](../flows/refresh_token.md) flow.
* The only way to expire an access token is to remove from the database.

### `refreshTokenLifetime`
The time in seconds where the refresh token will be valid. It defaults to `864000 sec` = 10 days.

In case you want a refresh token to never expire you can set this field to `null`.
Although it is not recommended, if you still want to never expire a refresh token,
take note of the following:
* The refresh token will not have an expiration date. Meaning the JWT expiration check will always pass.
* New refresh tokens will be generated from [`refreshToken`](../flows/refresh_token.md) flow, and it will replace the old refresh token.
* The only way to expire a refresh token is to remove from the database.

### `isTemporarilyUnavailable`
Used by the [`authorize`](functions_and_endpoints.md#authorize) function to check
if the server is undergoing maintenance, or is otherwise unavailable, the error code
`temporarily_unavailable`can be returned instead of responding with a 503 Service Unavailable
status code. It defaults to `false`.

This option also supports asynchronous calls:
```javascript
isTemporaryUnavailable: req => db.isNotAvailable();
```

### `validateRequest`
Used by the [`authorize`](functions_and_endpoints.md#authorize) function to validate a request.
By default, it will verify using the `user-agent` header if the request is from an embedded
WebView or from a bot and reject the request.

This option also supports asynchronous calls:
```javascript
validateRequest: req => isNotWebViewOrBot(req.headers['user-agent']);
```

Make note that it will not recognise malicious bots or programs that change their useragent string.

See also [Security considerations: X-Frame-Options](../security_consideration.md#x-frame-options).

### `isFlowAllowed`
Used by the [`authorize`](functions_and_endpoints.md#authorize),
[`token`](functions_and_endpoints.md#token)
and
[`deviceAuthorization`](functions_and_endpoints.md#device-authorization)
functions to check if the requested flow is allowed to be used from the client requesting.
It defaults to `true` for all clients.

This option also supports asynchronous calls:
```javascript
isFlowAllowed: (client_id, flowName, req) => true;
```

### `scopeDelimiter`
The delimiter that will be used to split the scope string.
It defaults to one space character (`' '`).

### `getClientCredentials`
Used by the
[`token`](functions_and_endpoints.md#token),
[`deviceAuthorization`](functions_and_endpoints.md#device-authorization),
[`introspection`](functions_and_endpoints.md#introspection),
[`revocation`](functions_and_endpoints.md#revocation)
functions to inquire the location of the client's credentials (`client id` & `client secret`).
The `client_id` is required to be present and the `client_secret` can be anything.

These credentials will be called later by the [`validateClient`](#validateclient) option.

There are 3 default locations:
* `header`: Basic authorization.
* `body`: Will take fields `client_id`, `client_secret` from the request's body.
* `query`: Will take fields `client_id`, `client_secret` from the request's query.

It defaults to `header`.

It is possible to use a custom location:
```javascript
function getClientCredentials(req) {
    return {
        client_id: req.query.client_id,
        client_secret: req.body.client_secret
    };
}
```

If `client id` or `client secret` is not found, return either `null`, `undefined`
or an empty string (falsy) in their place.

### `getUser`
Used by the [`authorize`](functions_and_endpoints.md#authorize) function and
[`Device Authorization`](../flows/device_authorization.md) flow to inquire about
the user's identification.

At the `authorize` function you have to provide the user's unique identification who authorized
a client from your `front-end` authorization page. If the authorization was declined
do not stop the flow and just return `null` (`oauth2` library will handle the rejection for you).

At the `Device Authorization` flow you have to provide the user's unique identification who authorized
a client from your `front-end` device authorization page. If the authorization was declined
do not stop the flow and just return `null` (`oauth2` library will handle the rejection for you).

Make not that the user's identification will be included to the JWT so:
* do not include sensitive information, that you don't want others to know.
* the identification must be either a primitive type or valid JSON.

It defaults to `req.user`:
```javascript
getUser: req => req.user;
```

An example on how it will be used with the [`authorize`](functions_and_endpoints.md#authorize) function:
```javascript
// isLoggedIn authenticates that the user is valid.
app.get('/oauth/v2/authorize', isUserLoggedIn, function (req, res, next) {
    // Check from your front-end that the user authorized the application.
    if(req.query.authorized === 'true')
        req.user = 'user-id' // Set the authenticated user's id.
    else
        req.user = null; // The use did not authorize the client.
    
    // Proccedd to next middleware
    next();
    // Call authorize function
}, authServer.authorize());
```

### `errorUri`
The server can also return a URL to a human-readable web page with information about the error.
This is intended for the developer to get more information about the error, and is not meant
to be displayed to the end user.

This field is used by all the flows and endpoints and can be overridden from the flows options.

### `audience`
Used by all the flows and to inquire about where the generated tokens are meant to be used.
It defaults to `baseUrl`, which specifies that is meant to be used only to authorization server.

This option also supports asynchronous calls.

```javascript
audience: 'https://example.com' // All tokens are generated only for example.com client

// For multiple clients or resource servers.
audience: (client_id, req) => {
    // ...
    return "audience";
}
```

### `deleteAfterUse`
Used by the
[`introspection`](functions_and_endpoints.md#introspection),
[`authenticate`](functions_and_endpoints.md#authenticate)
functions to inquire if an access token should be deleted after it is used.
It defaults to `false`.

### `allowAuthorizeMethodPOST`
Used by the
[`authorize`](functions_and_endpoints.md#authorize)
function to check if the authorization endpoint can be called
from the `POST` method (aside the `GET` method). It defaults to `false`.

If `true` data will be taken from the body of the request instead of the query.

### `validateClient`
Used by the
[`token`](functions_and_endpoints.md#token),
[`deviceAuthorization`](functions_and_endpoints.md#device-authorization),
[`introspection`](functions_and_endpoints.md#introspection),
[`revocation`](functions_and_endpoints.md#revocation)
functions to inquire if the credentials that was sent from the client are valid.

The parameters `client_id` & `client_secret` are coming from the result of the
[`getClientCredentials`](#getclientcredentials). In some cases like the
[`Device Authorization`](../flows/device_authorization.md) flow or when the client is public
the `client_secret` will not be present.

This option also supports asynchronous calls.

```javascript
validateClient: (client_id, client_secret, req) => {
    // ...
    return true;
}
```

### `issueRefreshTokenForThisClient`
Used by the
[`authorize`](functions_and_endpoints.md#authorize),
[`token`](functions_and_endpoints.md#token),
[`deviceAuthorization`](functions_and_endpoints.md#device-authorization)
functions to inquire if a refresh token will be generated for this client.
It will not generate a refresh token if the
[`Refresh Token`](../flows/refresh_token.md)
flow is not used.
It defaults tp `true` for all clients.

This option also supports asynchronous calls.

```javascript
issueRefreshTokenForThisClient: (client_id, req) => {
    return db.issueRefreshTokenFor(client_id);
}
```

Caution this will take effect only if the
[`Refresh Token`](../flows/refresh_token.md)
flow is implemented.

### `validateRedirectURI`
Used by the [`authorize`](functions_and_endpoints.md#authorize) function
to validate the client's id and redirect uri. It is highly recommended to pre-register
the redirect uris for your client to avoid open redirection or other attacks.
If the redirect uri is not present you should return `falsy`.

If the redirect uri is registered you can either return `true` or the redirect
uri itself. In the later case the `oauth2` library will check if the redirect uri
is the exact match of the one send by the client (in case of localhost it will
skip the port checking).

This option also supports asynchronous calls.

```javascript
validateRedirectURI: async (client_id, redirect_uri, req) => {
    if(!client_id || !redirect_uri) return false;
    
    return (await db.getClient(client_id, redirect_uri)).redirect_uri;
}
```

As documented in [here](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics#section-2.1):
```text
when comparing client redirect URIs against pre-registered URIs,
authorization servers MUST utilize exact string matching except for
port numbers in localhost redirection URIs of native apps
```

### `validateScopes`
Used by the
[`Device Authorization`](../flows/device_authorization.md),
[`Client Credentials`](../flows/client_credentials.md),
[`Resource Owner Credentials`](../flows/resource_owner_credentials.md)
flows and
[`authorize`](functions_and_endpoints.md#authorize),
function to inquire if the scopes send by the client are valid.
If the client does not send a scope string an empty array will be passed.

This option also supports asynchronous calls.

```javascript
validateScopes: (scopes, req) => scopes.every(scope => acceptedScopes.includes(scope));
```

In case you want to proceed with the request but omit invalid scopes you can return
a subset of the requested scopes. It is not mandatory to return a subset of the existing
scopes, but it is highly recommended.

```javascript
validateScopes: (scopes, req) => {
    if(!isScopesValid(scopes))
        return false;
    
    if(scopes.includes('no-valid-scope'))
        removeStringFromArray(scopes, 'no-valid-scope');
    
    return scopes;
}
```

You should return `false` if the scopes refer to different resource servers.

### `secret`
The `AuthorizationServer` uses JsonWebToken (JWT) for generating any kind of tokens.
JWT uses an option called `secret` to sign these tokens.
The tokens we sign are: `access tokens`, `refresh tokens` and `authorization codes`.

Take note that:
* The `secret` must be random, secure and not predictable (at least 32 random alphanumeric characters).
* The `secret` must never get leaked to anyone.
* If you want to change the `secret` keep in mind that all the tokens generated prio this change
will no longer be valid.

### `baseUrl`
The base URL of your authorization server. It will be used as the issuer in all generated
tokens and will be appended to the metadata endpoints.

Notes:
* It is required to be HTTPS. Only if the base URL is localhost it will allow HTTP.
* The URL must end with `/`.

### `saveTokens`
Used by all the flows to save the generated tokens to the database.
It should always return `true` unless the database did not save the tokens,
in that case you must return `false`.

This function also supports async calls.
```javascript
saveTokens: (data, req) => db.insert(data);
```

### `getAccessToken`
Used by the
[`authenticate`](functions_and_endpoints.md#authenticate),
[`introspection`](functions_and_endpoints.md#introspection),
[`revocation`](functions_and_endpoints.md#revocation)
functions to inquire if an access token is registered to the database.
If the access token still exists in the database you have to return it as it is,
otherwise `null`.

This function also supports async calls.

```javascript
getAccessToken: (data, req) => db.findTokens(data)?.accessToken;
```

### `getRefreshToken`
Used by the
[`revocation`](functions_and_endpoints.md#revocation)
function and
[`Refresh Token`](../flows/refresh_token.md)
flow to inquire if a refresh token is registered in the database.
If the refresh token still exists in the database you have to return it as it is,
otherwise `null`.

This function also supports async calls.

```javascript
getRefreshToken: (data, req) => db.findTokens(data)?.refreshToken;
```

### `revoke`
Used by the
[`revocation`](functions_and_endpoints.md#revocation),
[`authenticate`](functions_and_endpoints.md#authenticate),
[`introspection`](functions_and_endpoints.md#introspection)
functions and
[`Refresh Token`](../flows/refresh_token.md)
flow to ask for the revocation of a token or a record.
It must always return `true` unless the database did not delete the tokens or record, in that
case you must return `false`.

This function also supports async calls.

```javascript
revoke: (data, req) => {
    if(data.what === 'access_token')
        return db.deleteAccessToken(data.accessToken);
    else if(data.what === 'refresh_token')
        return db.deleteRefreshToken(data.refreshToken);
    else if(data.what === 'record')
        return db.deleteAllTokens(data.refreshToken);
}
```

### `metadata`
Used by the
[`metadata`](functions_and_endpoints.md#metadata)
function to inquire a set of information about the authorization server.
