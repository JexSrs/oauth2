# OAuth2
**OAuth2 | Various Implementations for open authorization**

This is a TypeScript implementation of OAuth2 as documented at RFC6749.
The [OAuth 2.0 Simplified](https://www.oauth.com/) was a significant help, while developing
this library, many thanks.
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

## Options

## Implementations

### Authorization code

#### Options

#### Passport

### Client credentials

#### Options

###  Device flow

#### Options

### Implicit

#### Options

### Refresh token

#### Options

### Resource owner credentials

#### Options

## Events

## Endpoints

### Authorize

### Token

### Device

### Introspection

### Authenticate

# Resource server

## Options

# Client

## Options
