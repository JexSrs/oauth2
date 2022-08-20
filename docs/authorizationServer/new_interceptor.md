# Register a mew interceptor
To create a new interceptor you have to inherit the
[`Interceptor`](./lib/components/interceptor.ts) interface and then
add them to your `AuthorizationServer` instance.

## Inherit the Interceptor interface
The interceptor interface has the following fields:

### `name`
The name of your interceptor. It should be unique by interceptor (not mandatory).

### `endpoint`
Can take the values: `authorize`, `token` and `device_authorization`.

This option will decide from which endpoint this interceptor will be called.

### `function`
The heart of your interceptor, where all the code will be written.

The parameters that will be passed are the following:
* `data`: an object containing useful information.
  * `req`: the request instance.
  * `serverOpts`: the options of the [`AuthorizationServer`](./authorization_server.md).
  * `clientId`: The authenticated client's id (aka `client_id`).
  * `response`: The successful OAuth2 response.
* `eventEmitter`: the event emitter that will emit all kinds of events.

You always have to return a response. That response will either be passed to another
interceptor or sent to the client.