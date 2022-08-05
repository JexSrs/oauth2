# Events
Using the NodeJs [`EventEmitter`](https://nodejs.dev/learn/the-nodejs-event-emitter) the `oauth2`
library provides a set of useful events to help you keep track the progress of all the flows.

## How to use
All you have to do is `import` the `Events` object and listen to the desired event:
```javascript
import {Events} from "oauth2";

authServer.on(Events.EVENT_NAME, function (req) {
  // ...
});
```

Each event is accompanied by the `request` instance of the current request.

Make note that exposing the `request` instance can cause security leaks. Why?
The `request` instance may contain sensitive information such as the `client_id`,
`client_secret`, `access tokens` or `refresh tokens`.

## Event types

### `INVALID_REDIRECT_URI`
Called from the [`authorize`](./functions_and_endpoints.md#authorize)
function when the [`validateRedirectURI`](./authorization_server.md#validateredirecturi) option
returns `false`.

Called from the [`Authorization Code`](../flows/authorization_code.md)
flow when the redirect uri passed at the second stage does not match
the redirect uri of the first stage.

### `INVALID_SCOPES`
Called from the [`authorize`](./functions_and_endpoints.md#authorize)
function and
[`Client Credentials`](../flows/client_credentials.md),
[`Device Authorization`](../flows/device_authorization.md),
[`Resource Owner Credentials`](../flows/resource_owner_credentials.md),
flows when the [`validateScopes`](./authorization_server.md#validatescopes) option
returns `false`.

### `INVALID_CLIENT`
Called from the
[`Authorization Code`](../flows/authorization_code.md)
flow at the second stage when [`validateClient`](./authorization_server.md#validateclient) option
returns `false`.

Called from the
[`Device Authorization`](../flows/device_authorization.md)
flow at the first stage when [`validateClient`](./authorization_server.md#validateclient) option
returns `false`.

Called by the
[`Client Credentials`](../flows/client_credentials.md),
[`Refresh Token`](../flows/refresh_token.md),
[`Resource Owner Credentials`](../flows/resource_owner_credentials.md),
flows when [`validateClient`](./authorization_server.md#validateclient) option
returns `false`.

### `INVALID_REQUEST`
Called from the [`authorize`](./functions_and_endpoints.md#authorize)
function when the [`validateRequest`](./authorization_server.md#validaterequest) option
returns `false`.

### `ACCESS_DENIED`
Called from the [`authorize`](./functions_and_endpoints.md#authorize)
function when the [`getUser`](./authorization_server.md#getuser) option
returns `null`. 

Called from the [`Device Authorization`](../flows/device_authorization.md)
flow at the second stage when the
[`getUser`](../flows/device_authorization.md#getuser)
option returns `null`.

### `UNSUPPORTED_RESPONSE_TYPE`
Called from the [`authorize`](./functions_and_endpoints.md#authorize)
function when no flow is found to support the requested `response_type`.

### `UNSUPPORTED_GRANT_TYPE`
Called from the
[`token`](./functions_and_endpoints.md#token),
[`deviceAuthorization`](./functions_and_endpoints.md#device-authorization)
functions when no flow is found to support the requested `grant_type`.

### `REJECTED_FLOW`
Called from the
[`authorize`](./functions_and_endpoints.md#authorize),
[`token`](./functions_and_endpoints.md#token),
[`deviceAuthorization`](./functions_and_endpoints.md#device-authorization)
functions when the [`isFlowAllowed`](./authorization_server.md#isflowallowed)
option returns `false`.

### `FAILED_TOKEN_SAVE`
Called by all the flows when the [`saveTokens`](./authorization_server.md#savetokens)
option returns `false`.

### `FAILED_AUTHORIZATION_CODE_SAVE`
Called from the
[`Authorization Code`](../flows/authorization_code.md)
flow at the first stage when the
[`saveAuthorizationCode`](../flows/authorization_code.md#saveauthorizationcode)
option returns `false`.

### `FAILED_DEVICE_CODE_SAVE`
Called from the
[`Device Authorization`](../flows/device_authorization.md)
flow at the first stage when the
[`saveDevice`](../flows/device_authorization.md#savedevice)
option returns `false`.

### `INVALID_PKCE`
Called from the
[`Authorization Code`](../flows/authorization_code.md)
flow at the first stage when
[`usePKCE`](../flows/authorization_code.md#usepkce)
is `true` and the fields `code_challenge`, `code_challenge_method`are not defined.
Also called when the
[`validCodeChallengeMethods`](../flows/authorization_code.md#validcodechallengemethods)
option returns `false`

Called from the
[`Authorization Code`](../flows/authorization_code.md)
flow at the second stage when
[`usePKCE`](../flows/authorization_code.md#usepkce)
is `true` and the
[`hashCodeChallenge`](../flows/authorization_code.md#hashcodechallenge)
option does not return the expected code challenge.

### `INVALID_AUTHORIZATION_CODE_TOKEN_JWT`
Called from the
[`Authorization Code`](../flows/authorization_code.md)
flow at the second stage when the authorization code
that was (supposedly) generated at the first stage does not pass
the JWT verification.

### `INVALID_AUTHORIZATION_CODE_TOKEN_CLIENT`
Called from the
[`Authorization Code`](../flows/authorization_code.md)
flow at the second stage when the authorization code
that was generated at the first stage is used by another client.

### `INVALID_AUTHORIZATION_CODE_TOKEN_DB`
Called from the
[`Authorization Code`](../flows/authorization_code.md)
flow at the second stage when the
[`getAuthorizationCode`](../flows/authorization_code.md#getauthorizationcode)
option does not return the expected authorization code (possibly revoked).

### `SLOW_DOWN`
Called from the
[`Device Authorization`](../flows/device_authorization.md)
flow at the second stage when the client makes a request that
does not respect the [`interval`](../flows/device_authorization.md#interval)
option.

### `INVALID_DEVICE_CODE`
Called from the
[`Device Authorization`](../flows/device_authorization.md)
flow at the second stage when the
[`getDevice`](../flows/device_authorization.md#getdevice)
option does not return the expected record (possibly not registered from stage 1)

### `EXPIRED_DEVICE_CODE`
Called from the
[`Device Authorization`](../flows/device_authorization.md)
flow at the second stage when the device code has expired

### `REQUEST_PENDING`
Called from the
[`Device Authorization`](../flows/device_authorization.md)
flow at the second stage when the record status is still `pending`,
meaning the user has not yet authorized the application.

### `INVALID_USER`
Called from the
[`Resource Owner Credentials`](../flows/resource_owner_credentials.md),
flow when the
[`validateUser`](../flows/resource_owner_credentials.md#validateuser)
option returned `null`.

### `INVALID_REFRESH_TOKEN_JWT`
Called from the
[`Refresh Token`](../flows/refresh_token.md)
flow when the refresh token does not pass the JWT verification.

### `INVALID_REFRESH_TOKEN_NOT`
Called from the
[`Refresh Token`](../flows/refresh_token.md)
flow when the token presented is not a refresh token.

### `INVALID_REFRESH_TOKEN_SCOPES`
Called from the
[`Refresh Token`](../flows/refresh_token.md)
flow when the requested scope includes additional scopes that were
not issued in the original access token.

### `INVALID_REFRESH_TOKEN_CLIENT`
Called from the
[`Refresh Token`](../flows/refresh_token.md)
flow when the refresh token is used by another client.

### `INVALID_REFRESH_TOKEN_DB`
Called from the
[`Refresh Token`](../flows/refresh_token.md)
flow when the
[`getRefreshToken`](./authorization_server.md#getrefreshtoken)
option does not return the expected refresh token (possibly revoked).

### `AUTHENTICATION_MISSING_TOKEN`
Called from the
[`authenticate`](./functions_and_endpoints.md#authenticate)
function when the
[`getToken`](./authorization_server.md#gettoken)
option not found the access token.

### `AUTHENTICATION_INVALID_TOKEN_JWT`
Called from the
[`authenticate`](./functions_and_endpoints.md#authenticate)
function when the token is not valid or has expired.

### `AUTHENTICATION_INVALID_TOKEN_NOT`
Called from the
[`authenticate`](./functions_and_endpoints.md#authenticate)
function when the token is not an access token.

### `AUTHENTICATION_INVALID_TOKEN_DB`
Called from the
[`authenticate`](./functions_and_endpoints.md#authenticate)
function when the
[`getAccessToken`](./authorization_server.md#getaccesstoken)
option did not return the expected access token (possibly revoked)

### `AUTHENTICATION_INVALID_TOKEN_SCOPES`
Called from the
[`authenticate`](./functions_and_endpoints.md#authenticate)
function when the scopes of the access token does not
suffice for this endpoint.

## Override emitter
You can also override the default emitter with one of your own:
```javascript
authServer.eventEmitter = new MyCustomEmitter();
// or
authServer.eventEmitter.emit = function (eventName, ...args) {
  super.emit(eventName, ...args);
  
  super.emit("*", ...args);
}
```
