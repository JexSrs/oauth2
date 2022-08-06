# OAuth2

## Table of contents
* [Introduction & Specifications](#introduction--specifications)
  * [Notes](#notes)
* [Installation](#installation)
* [Authorization server](#authorization-server)
  * [Flows](#flows)
  * [Events](#events)
  * [Functions & Endpoints](#functions--endpoints)
  * [State](#state)
* [Resource server](#resource-server)
* [Security considerations](#security-considerations)

## Introduction & Specifications
**OAuth2 | Various Implementations for open authorization**

This is a TypeScript implementation of OAuth2 as documented at [RFC6749](https://datatracker.ietf.org/doc/html/rfc6749).
Many thanks to the [OAuth 2.0 Simplified](https://www.oauth.com/) website. It was a significant help as
a starting point while developing this library.

You can see with more detail the specs that was used below:

* [RFC6749](https://datatracker.ietf.org/doc/html/rfc6749): OAuth 2.0 Core
* [RFC6750](https://datatracker.ietf.org/doc/html/rfc6750): Bearer Tokens
* [RFC6819](https://datatracker.ietf.org/doc/html/rfc6819): Threat Model and Security Consideration
* [RFC7009](https://datatracker.ietf.org/doc/html/rfc7009): Token Revocation
* [RFC7636](https://datatracker.ietf.org/doc/html/rfc7636): PKCE Extension
* [RFC7662](https://datatracker.ietf.org/doc/html/rfc7662): Token Introspection
* [RFC8252](https://datatracker.ietf.org/doc/html/rfc8252): OAuth 2.0 for Native Apps
* [RFC8628](https://datatracker.ietf.org/doc/html/rfc8628): Device Authorization Grant
* [RFC9068](https://datatracker.ietf.org/doc/html/rfc9068): JWT Profile for OAuth 2.0 Access Tokens
* [RFC9101](https://datatracker.ietf.org/doc/html/rfc9101): JWT-Secured Authorization Request
* [OAuth 2.0 Security Best Current Practice](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics)

### Notes
* [RFC9068](https://datatracker.ietf.org/doc/html/rfc9068) (JWT Profile for OAuth 2.0 Access Tokens)
  * The claim `sub` (subject) must contain the user's or client'd id.
The user's id in this library can be any valid json or primitive type which does not comply
with the claim's (`sub`) type which is string. It will be replaced inside the payload by the field `user`.
  * The parameter `resource` will not be used, instead the Authorization Server
should decide the `audience` claim using the [`audience`](./docs/authorizationServer#audience)
option.

## Installation
This library is not in [npm](https://www.npmjs.com/). To use it you have to clone the repository to
your machine and use the `link` command:

```shell
# Clone
git clone https://github.com/JexSrs/oauth2.git
# Go to your project
cd my-project
# and link
npm link ../oauth2
```

## Authorization server
The core of this library, it will create `Express` end-middlewares that will be attached
to your server and handle the oauth requests.

```javascript
import {AuthorizationServer, authorizationCode} from "oauth2";

// Create new instance
const authServer = new AuthorizationServer({/* options */});

// Register a new flow
authServer.use(authorizationCode({/* options */}));

// Register endpoints
app.get('/oauth/v2/authorize', isLoggedIn, authServer.authorize());
app.post('/oauth/v2/token', authServer.token());
```

Click [here](./docs/authorization_server.md) for more details about the authorization server.

### Flows
`Flow` refers to an OAuth2 `Grant Type`. The [`AuthorizationServer`](docs/authorizationServer/authorization_server.md)
can implement one or more different flows, without one affecting the other.

The `oauth2` library comes together with some of the most popular flows:
* [`Authorization Code`](./docs/authorization_code.md)
* [`Client Credentials`](./docs/client_credentials.md)
* [`Device Authorization`](./docs/device_authorization.md)
* [`Implicit`](./docs/implicit.md)
* [`Refresh Token`](./docs/refresh_token.md)
* [`Resource Owner Credentials`](./docs/resource_owner_credentials.md)

If the flows above does not match your needs you can always create one for yourself.
To create one you have to inherit the [`Flow`](./lib/components/flow.ts) interface and like the
rest of the flows above import them to your `AuthorizationServer` instance:

```javascript
authServer.use(my_flow);
```

Click [here](docs/authorizationServer/new_flow.md) for mor details about how to create a new flow.

### Events
Using the NodeJs [`EventEmitter`](https://nodejs.dev/learn/the-nodejs-event-emitter) the `oauth2`
library provides a set of useful events to help you keep track the progress of all the flows.

All you have to do is `import` the `Events` object and listen to the desired event:
```javascript
import {Events} from "oauth2";

authServer.on(Events.EVENT_NAME, function (req) {
    // ...
});
```

Click [here](docs/authorizationServer/events.md) for more details about the `oauth2` events.

### Functions & Endpoints
The [`AuthorizationServer`](docs/authorizationServer/authorization_server.md) instance provides
some functions to assign to your endpoints to expose the OAuth2 flows to your
[`Express`](https://expressjs.com/) server.

These functions are:
* `authorize`: To expose the authorization flow (where the user authorizes an application).
* `token`: To expose the token flow (where an app requests for tokens).
* `device`: Used for the [`Device Authorization`](./docs/flows/device_authorization.md) flow.
* `introspection`: A mechanism for the resource servers to obtain information about access tokens.
* `revocation`: To allow access or refresh tokens revocation.
* `authenticate`: A way to authenticate access tokens (if authorization and resource server are the same).

Click [here](docs/authorizationServer/functions_and_endpoints.md) for more details about functions and endpoints.

### State
If you have read all the documentation so far I am sure you have noticed how all options that provide
a function (method) also pass an `Ecpress Request` instance of the current request. Using that object
you can create a state between the called option functions (methods).

For example:
```javascript
// During authorization
validateRedirectURI: async (client_id, redirect_uri, req) => {
    return !!(await db.findClient(client_id, redirect_uri));
}

// And then during scope validation
validateScopes: async (scopes, req) => {
    const client = await db.findClient(client_id, redirect_uri);
    return scopes.every(scope => client.scopes.includes(scope));
}
```
can be transformed into this:
```javascript
// During authorization
validateRedirectURI: async (client_id, redirect_uri, req) => {
    const client = await db.findClient(client_id, redirect_uri);
    if(!client) return false;

    // The scopes a client is allowed to request.
    // Depending on the implementation in may be all the available scopes
    req.scopes = client.scopes;
    return true;
}

// And then during scope validation
// One less request.
validateScopes: (scopes, req) => scopes.every(scope => req.scopes.includes(scope));
```

To be able to achieve this, the order where the options are called is necessary.

Read more at the break-down section of the
[`functions`](./docs/authorizationServer/functions_and_endpoints.md)
and about [`each flow`](./docs/flows). 

## Resource server
The resource server is the OAuth 2.0 term for your API server. The resource server handles
authenticated requests after the application has obtained an access token.

```javascript
import {ResourceServer} from "oauth2";

const resoourceServer = new ResourceServer({/* options */});
```

Click [here](./docs/resource_server.md) for more details about the resource server.

## Security Considerations
The `oauth2` library will try its best to protect you from outside threats, but the problems
does not end there. Leakage of codes and access tokens can happen from the authorization server
or the client's side.

Click [here](./docs/security_consideration.md) for more details.