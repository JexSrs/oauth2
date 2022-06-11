# OAuth2
**OAuth2 | Various Implementations for open authorization**

This is a TypeScript implementation of OAuth2 as documented at [RFC6749](https://datatracker.ietf.org/doc/html/rfc6749).
Many thanks to the [OAuth 2.0 Simplified](https://www.oauth.com/) website. It was a significant help while developing
this library.
You can see with more detail the specs that was used below:

* OAuth 2.0 Core: [RFC6749](https://datatracker.ietf.org/doc/html/rfc6749)
* Bearer tokens: [RFC6750](https://datatracker.ietf.org/doc/html/rfc6750)
* PKCE: [RFC7636](https://datatracker.ietf.org/doc/html/rfc7636)
* Threat Model and Security Consideration: [RFC6819](https://datatracker.ietf.org/doc/html/rfc6819)
* [OAuth 2.0 Security Best Current Practice](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics)
* Token Introspection: [RFC7662](https://datatracker.ietf.org/doc/html/rfc7662)
* JWT Profile for OAuth Access Tokens: [RFC9068](https://datatracker.ietf.org/doc/html/rfc9068)
* Device Authorization Grant: [RFC8628](https://datatracker.ietf.org/doc/html/rfc8628)
* JWT Authorization Request: [RFC9101](https://datatracker.ietf.org/doc/html/rfc9101)

Some more SPECS will be implemented in the feature from [here](https://www.oauth.com/oauth2-servers/map-oauth-2-0-specs/).

# Table of contents
* [Installation](#installation)
* [Authorization server](#authorization-server)
  * [Options](#options)
  * [Implementations](#implementations)
    * [Authorization code](#authorization-code)
      * [Options](#options-1)
      * [Passport](#passport)
    * [Client credentials](#client-credentials)
      * [Options](#options-2)
    * [Device flow](#device-flow)
        * [Options](#options-3)
    * [Implicit](#implicit)
        * [Options](#options-4)
    * [Refresh token](#refresh-token)
        * [Options](#options-5)
    * [Resource owner credentials](#resource-owner-credentials)
      * [Options](#options-6)
    * [Add custom](#add-custom)
  * [Events](#events)
  * [Endpoints](#endpoints)
    * [Authorize](#authorize)
    * [Token](#token)
    * [Device](#device)
    * [Introspection](#introspection)
    * [Authenticate](#authenticate)
* [Resource server](#resource-server)
  * [Options](#options-7)
* [Client](#client)
    * [Options](#options-8)


# Installation
```shell
# Add repository as dependency 
```

# Authorization server
The core of this library, it will create `Express` middlewares that will be attached
to your server and handle the oauth requests.

```javascript
import {AuthorizationServer} from "oauth2";

const authServer = new AuthorizationServer({/* options */});
```

## Options

The authorization server has globalized some options that are needed for almost
all the implementations. For more details go see the
[`AuthorizationServerOptions`](./lib/implementations/authorizationCode/authorizationCodeOptions.ts).

## Implementations
`Implementation` is an oauth flow the authorization server supports.
The authorization server has an abstract form, this helps to add more
implementations without needing to edit the server itself.

To add an implementation to the server:
```javascript
authServer.use(implementation);
```

Below you can see the supported oauth flows:

### Authorization code

```javascript
import {authorizationCode} from "oauth2";

authServer.use(authorizationCode({/* options */}));
```

#### Options
The authorization flow has extra options. For more details go see the
[`AuthorizationCodeOptions`](./lib/implementations/authorizationCode/authorizationCodeOptions.ts)
and [`Common`](./lib/components/common.ts) options.

#### Passport
This library is compatible with passport authorization code flow.
For more information about passport see [Passport.js](https://www.passportjs.org/)
and [passport-oauth2](https://www.passportjs.org/packages/passport-oauth2/).

### Client credentials

```javascript
import {clientCredentials} from "oauth2";

authServer.use(clientCredentials({/* options */}));
```

#### Options
The client credentials flow has extra options. For more details go see the
[`ClientCredentialsOptions`](./lib/implementations/clientCredentials/clientCredentialsOptions.ts)
and [`Common`](./lib/components/common.ts) options.

###  Device flow

```javascript
import {deviceFlow} from "oauth2";

authServer.use(deviceFlow({/* options */}));
```

#### Options
The device flow has extra options. For more details go see the
[`DeviceFlowOptions`](./lib/implementations/deviceFlow/deviceFlowOptions.ts).

### Implicit

```javascript
import {implicit} from "oauth2";

authServer.use(implicit({/* options */}));
```

#### Options
The implicit flow does not have extra options.

### Refresh token

```javascript
import {refreshToken} from "oauth2";

authServer.use(refreshToken({/* options */}));
```

#### Options
The refresh token flow has extra options. For more details go see the
[`RefreshTokenOptions`](./lib/implementations/refreshToken/refreshTokenOptions.ts)
and [`Common`](./lib/components/common.ts) options.

### Resource owner credentials

```javascript
import {resourceOwnerCredentials} from "oauth2";

authServer.use(resourceOwnerCredentials({/* options */}));
```

#### Options
The resource owner credentials flow has extra options. For more details go see the
[`ResourceOwnerCredentialsOptions`](./lib/implementations/resourceOwnerCredentials/resourceOwnerCredentialsOptions.ts)
and [`Common`](./lib/components/common.ts) options.

### Add custom
The authorization server can support flows that are not accompanied from this library.
To create one you have to inherit the [`Implementation`](./lib/components/implementation.ts) interface.

## Events
With the help of Node.js [`Event Emitter`](https://nodejs.dev/learn/the-nodejs-event-emitter),
the authorization library emits some useful events. You can listen to those events
using:

```javascript
import {Events} from "oauth2";

authServer.on(Events.AUTHORIZATION_REDIRECT_URI_INVALID, function (req) {
    // ...
});
```

Each event is accompanied by the request instance of current request.
For example this can be used for logging, or checking if an
authorization code is used twice.

**Caution!** this can be a security problem if not handled right, because it
may expose credentials such as `client_id`, `client_secret`, `access tokens` or
`refresh tokens`.

### Authorization endpoint
* `AUTHORIZATION_REDIRECT_URI_INVALID`: If the client passes an invalid redirect uri
at authorization.
* `AUTHORIZATION_SCOPES_INVALID`: The scopes the client passed are not valid.
* `AUTHORIZATION_USERGAENT_INVALID`: The user agent did not pass the checks (embedded web view, bot).
* `AUTHORIZATION_RESPONSE_TYPE_UNSUPPORTED`: The client asked for an implementation at the authorization endpoint that does not exist.
* `AUTHORIZATION_RESPONSE_TYPE_REJECT`: The client is no eligible for this implementation.

#### Authorization Code
* `AUTHORIZATION_FLOWS_CODE_PKCE_INVALID`: PKCE arguments were missing or invalid.
* `AUTHORIZATION_FLOWS_CODE_SAVE_ERROR`: Function `saveTokens` returned false (did not succeed).

#### Implicit
* `AUTHORIZATION_FLOWS_TOKEN_SAVE_ERROR`: Function `saveTokens` returned false (did not succeed).

### Token endpoint
* `TOKEN_GRANT_TYPE_UNSUPPORTED`: The client asked for an implementation at the token endpoint that does not exist.

#### Authorization Code
* `TOKEN_FLOWS_AUTHORIZATION_CODE_TOKEN_JWT_INVALID`: The authorization code did not pass the JWT authentication (expired or invalid).
* `TOKEN_FLOWS_AUTHORIZATION_CODE_TOKEN_CLIENT_INVALID`: The authorization code does not belong to the client_id.
* `TOKEN_FLOWS_AUTHORIZATION_CODE_TOKEN_DB_INVALID`: The authorization code not found in the database.
* `TOKEN_FLOWS_AUTHORIZATION_CODE_CLIENT_INVALID`: Client did not pass the authentication (`client_id` and `client_secret`).
* `TOKEN_FLOWS_AUTHORIZATION_CODE_REDIRECT_URI_INVALID`: The redirect uri is not the same as the one that generated the authorization code.
* `TOKEN_FLOWS_AUTHORIZATION_CODE_PKCE_INVALID`: The PKCE protection failed.
* `TOKEN_FLOWS_AUTHORIZATION_CODE_SAVE_ERROR`: Function `saveTokens` returned false (did not succeed).

#### Client credentials
* `TOKEN_FLOWS_CLIENT_CREDENTIALS_SCOPES_INVALID`: The scopes the client passed are not valid.
* `TOKEN_FLOWS_CLIENT_CREDENTIALS_CLIENT_INVALID`: Client did not pass the authentication (`client_id` and `client_secret`).
* `TOKEN_FLOWS_CLIENT_CREDENTIALS_SAVE_ERROR`: Function `saveTokens` returned false (did not succeed).

#### Device flow
* `TOKEN_FLOWS_DEVICE_CODE_SLOW_DOWN`: The client made a request too early.
* `TOKEN_FLOWS_DEVICE_CODE_DEVICE_CODE_INVALID`: Device code not found in database.
* `TOKEN_FLOWS_DEVICE_CODE_EXPIRED`: The client made a request and the response was `expired_token`.
* `TOKEN_FLOWS_DEVICE_CODE_PENDING`: The client made a request and the response was `authorization_pending`.
* `TOKEN_FLOWS_DEVICE_CODE_ACCESS_DENIED`: The client made a request and the response was `access_denied` (the user denied the authorization).
* `TOKEN_FLOWS_DEVICE_CODE_SAVE_ERROR`: Function `saveTokens` returned false (did not succeed).

#### Resource owner credentials
* `TOKEN_FLOWS_PASSWORD_SCOPES_INVALID`: The scopes the client passed are not valid.
* `TOKEN_FLOWS_PASSWORD_CLIENT_INVALID`: Client did not pass the authentication (`client_id` and `client_secret`).
* `TOKEN_FLOWS_PASSWORD_USER_INVALID`: User sent invalid credentials
* `TOKEN_FLOWS_PASSWORD_SAVE_ERROR`: Function `saveTokens` returned false (did not succeed).

#### Refresh token
* `TOKEN_FLOWS_REFRESH_TOKEN_TOKEN_JWT_INVALID`: The refresh token did not pass the JWT authentication.
* `TOKEN_FLOWS_REFRESH_TOKEN_TOKEN_NOT_REFRESH_TOKEN`: The passed token was not a refresh token.
* `TOKEN_FLOWS_REFRESH_TOKEN_SCOPES_INVALID`: The scopes the client passed are not valid.
* `TOKEN_FLOWS_REFRESH_TOKEN_CLIENT_INVALID`: The refresh token does not belong to client id, or client authentication failed.
* `TOKEN_FLOWS_REFRESH_TOKEN_TOKEN_DB_INVALID`: The refresh token not found in the database.
* `TOKEN_FLOWS_REFRESH_TOKEN_SAVE_ERROR`: Function `saveTokens` returned false (did not succeed).

### Device endpoint
* `DEVICE_GRANT_TYPE_UNSUPPORTED`: The client asked for an implementation at the device endpoint that does not exist.
* `DEVICE_SCOPES_INVALID`: The scopes the client passed are not valid.

#### Device flow
* `DEVICE_FLOWS_TOKEN_CLIENT_INVALID`: Client did not pass authentication (`client_id` not registered).
* DEVICE_FLOWS_TOKEN_SAVE_ERROR: Function `saveTokens` returned false (did not succeed).

### Authentication endpoint
* `AUTHENTICATION_TOKEN_MISSING`: No token provided when authenticating a request.
* `AUTHENTICATION_TOKEN_JWT_EXPIRED`: The access token did not pass the JWT authentication.
* `AUTHENTICATION_TOKEN_DB_EXPIRED`: The access token not found in the database.
* `AUTHENTICATION_TOKEN_NOT_ACCESS_TOKEN`: The token is not an access token.
* `AUTHENTICATION_SCOPES_INVALID`: The scopes of the access token are insufficient.

## Endpoints
The authorization server provides some endpoints that will be assigned to your Express server.
For example:
```javascript
app.get('/oauth/v2/authorize', authServer.authorize());
```

### Authorize
The authorization endpoint. This endpoint is called when the user is authorizing the application.
In this endpoint you have to authenticate the user before reaching the `authorize` function.
For example:

```javascript
app.get('/oauth/v2/authorize', function (req, res, next) {
    if(userAuthenticated(req)) {
        req.user = {/* user's identification */};
        next();
    }
    
    res.end('User is not authenticated.');
}, authServer.authorize());
```

The authorization endpoint must be accessed with the method `GET` and all data are accessed
from the query.

Before reaching the desired implementation, the authorization endpoint will call the following
functions, so that it can to some basic checks:
* validateRedirectURI
* isTemporaryUnavailable
* rejectEmbeddedWebViews
* isGrantTypeAllowed
* isScopesValid

All these functions are initialized at the [AuthorizationServerOptions](#options)

### Token
The token endpoint. This endpoint is called from the client directly without the need to
authorize the user. Each flow will require the user to identify itself (e.x. `client_secret`).
For example:

```javascript
app.post('/oauth/v2/token', authServer.token());
```

The token endpoint must be accessed with the method `POST` and all data are accessed
from the body. The oauth2 specifies that the data are in query form (e.x. `name=mike&age=16`),
so you have to use the `urlEncoded` body parser with `extended` set to `true`.

```javascript
app.post('/oauth/v2/token',
    express.urlencoded({type: "application/x-www-form-urlencoded", extended: true}),
    authServer.token());
```
or
```javascript
app.use(express.urlencoded({type: "application/x-www-form-urlencoded", extended: true}));
app.post('/oauth/v2/token', authServer.token());
```

### Device
The device endpoint. Like token, this endpoint will be called from the client directly
without the need to authorize the user. This endpoint is used for the first phase of the device flow.

```javascript
app.post('/oauth/v2/device', authServer.device());
```

The device endpoint must be accessed with the method `POST` and all data are accessed
from the body.

### Introspection
The introspection endpoint. Unlike the others, this endpoint is used by the resource server(s)
and is meant to be private to only them. When a request arrives to the resource server to access
a protected content, the resource server will send the token that accompanies the request to
the authorization server and ask if it is valid. The authorization server will respond with
a json that contains if it is `active` and some other information about the token.

```javascript
app.post('/oauth/v2/introspection', authServer.introspection());
```

The introspection endpoint must be accessed with the method `POST` and all data are accessed
from the body.

### Authenticate
This is more like a functionality and not an endpoint. There are cases where the
authorization server and the resource server are one and the same. In these case, the
function `authenticate` will act as a middleware to authenticate the request before accessing
the protected content.

```javascript
app.get('/protected', authServer.authenticate(), function (req, res) {
    // ...
});
```

This function does not limit the used method.

If you want to authenticate a protected resource based on a specific scope then
pass as the first argument the scopes you want to be required.

```javascript
authServer.authenticate('scope1');
```
or with multiple scopes
```javascript
// Access token must have all scopes present
authServer.authenticate(['scope1', 'scope2', 'scope3'], 'all'); // Default

// Access token must have at least one of them.
authServer.authenticate(['scope1', 'scope2', 'scope3'], 'some');
```

# Resource server

## Options

# Client

## Options
