# Register a mew flow
To create a new flow you have to inherit the [`Flow`](./lib/components/flow.ts) interface and like
the built-in flows import them to your `AuthorizationServer` instance.

Before starting creating your own flow, you should read the rest of the documentation
to understand the terminology that will be used below.

## Inherit the Flow interface
The flow interface has the following fields:

### `name`
The name of your flow. It should be unique by flow.

For example the [`Authorization Code`](../flows/authorization_code.md) flow has two stages
and both stages have the same `name`

### `endpoint`
Can take the values: `authorize`, `token` and `device_authorization`.

This option will decide from which endpoint this flow will be accessible.

### `matchType`
The `response_type` or `grant_type` that has to be matched to access this flow.

### `function`
The heart of your flow, where all the code of your flow will run.

The parameters that will be passed are the following:
* `data`: an object containing useful information.
  * `req`: the request instance.
  * `serverOpts`: the options of the [`AuthorizationServer`](./authorization_server.md).
  * `issueRefreshToken`: Whether a refresh token will be issued or not.
  * `clientId`: The authenticated client's id (aka `client_id`).
  * `scopes`: Accessible only from the [`authorize`] endpoint, it will contain the requested scopes.
  * `user`: Accessible only from the [`authorize`] endpoint, it will contain the user's id.
* `callback`: It will return the response or an error.
```javascript
// Successful response
callback({
    access_token: ...,
    refresh_token: ...,
    // ...
});

// Error response:
callback(undefined, {
    error: 'error_message',
    error_description: 'error_description',
    error_uri: 'error_uri',
    status: 400 // Will be omitted in `authorize` endpoint
});
```
* `eventEmitter`: the event emitter that will emit all kinds of events.

## Multiple stages
For flows that have multiple stages like the
[`Authorization Code`](../flows/authorization_code.md)
and
[`Device Authorization`](../flows/device_authorization.md)
flows you have to inherit the Flow interface in multiple objects.
