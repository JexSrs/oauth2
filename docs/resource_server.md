# Resource Server
The resource server is the OAuth 2.0 term for your API server. The resource server handles
authenticated requests after the application has obtained an access token.

`Large scale` deployments may have more than one resource server.
`Smaller scale` deployments typically have only one resource server,
and is often built as part of the same code base or same deployment as the authorization server.
For this case read about the `authenticate` endpoint at the `AuthorizationServer`.

## How to use
```javascript
import {ResourceServer} from "oauth2";

const resoourceServer = new ResourceServer({/* options */});
```

## Options

### `getToken`
Used by the `authenticate` function of the `ResourceServer` to inquire about the
location of the access token. It defaults to the authorization header:

```javascript
getToken: req => req.headers['authorization']?.split(' ')?.[1];
```

In the example above the authorization header will look like: `Bearer <token>`.
Make note that you have to return the `<token>` part only.

### `setPayloadLocation`
Used by the `authenticate` function of the `ResourceServer` to inquire about the
where to save the `payload` if the authentication succeeds. It defaults to `req.payload`:

```javascript
setPayloadLocation: (req, payload) => req.payload = payload;
```

### `headers`
Used by the `authenticate` function of the `ResoureServer` to inquire extra any headers
that will be sent to the
[`introspection`](./authorizationServer/functions_and_endpoints.md#introspection)
endpoint.

It defaults to `{'Content-Type': 'application/x-www-form-urlencoded'}`.

### `body`
Used by the `authenticate` function of the `ResoureServer` to inquire if a body will
be sent alongside the `token` to the
[`introspection`](./authorizationServer/functions_and_endpoints.md#introspection)
endpoint.

For example if the authentication must be done from the body instead of the headers
you can include your credentials here.

### `scopeDelimiter`
The delimiter that will be used to split the scope string.
It defaults to one space character (`' '`).

### `errorUri`
The server can also return a URL to a human-readable web page with information about the error.
This is intended for the developer to get more information about the error, and is not meant
to be displayed to the end user.

### `introspectionURL`
Used by the `authenticate` function of the `ResoureServer` to inquire the location
of the [`introspection`](./authorizationServer/functions_and_endpoints.md#introspection)
endpoint.

### `audience`
The resource server's `audience`. It will be used to inquire if the token send to the
[`AuthorizationServer`](./authorizationServer/authorization_server.md)
through the [`introspection`](./authorizationServer/functions_and_endpoints.md#introspection)
endpoint is meant to be used to the current `ResourceServer`.
