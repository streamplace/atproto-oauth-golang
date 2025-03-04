# Atproto OAuth Golang

> [!WARNING]  
> This is an experimental repo. It may contain bugs. Use at your own risk.

> [!WARNING]
> You should always validate user input. The example/test code inside this repo may be used as an implementation guide, but no guarantees are made.

```bash
go get github.com/haileyok/atproto-oauth-golang
```

## Prerequisites
There are some prerequisites that you'll need to handle before implementing this OAuth client.

### Private JWK
If you do not already have a private JWK for your application, first create one. There is a helper CLI tool that can generate one for you. From the project directory, run

`make jwks`

You will need to read the JWK from your application and parse it using `oauth.ParseJWKFromBytes`. 

### Serve `client-metadata.json` from your application

The client metadata will need to be accessible from your domain. An example using `echo` is below.

```go
func (s *TestServer) handleClientMetadata(e echo.Context) error {
	metadata := map[string]any{
		"client_id":                       serverMetadataUrl,
		"client_name":                     "Atproto Oauth Golang Tester",
		"client_uri":                      serverUrlRoot,
		"logo_uri":                        fmt.Sprintf("%s/logo.png", serverUrlRoot),
		"tos_uri":                         fmt.Sprintf("%s/tos", serverUrlRoot),
		"policy_url":                      fmt.Sprintf("%s/policy", serverUrlRoot),
		"redirect_uris":                   []string{serverCallbackUrl},
		"grant_types":                     []string{"authorization_code", "refresh_token"},
		"response_types":                  []string{"code"},
		"application_type":                "web",
		"dpop_bound_access_tokens":        true,
		"jwks_uri":                        fmt.Sprintf("%s/oauth/jwks.json", serverUrlRoot),
		"scope":                           "atproto transition:generic",
		"token_endpoint_auth_method":      "private_key_jwt",
		"token_endpoint_auth_signing_alg": "ES256",
	}

	return e.JSON(200, metadata)
}
```

### Serve `jwks.json`

You will also need to serve your private JWK's __public key__ from your domain. Again, an example is below.

```go
func (s *TestServer) handleJwks(e echo.Context) error {
    b, err := os.ReadFile("./jwk.json")
    if err != nil {
        return err
    }

    k, err := oauth.ParseJWKFromBytes(b)
    if err != nil {
        return err
    }

    pubKey, err := k.PublicKey()
    if err != nil {
        return err
    }

    return e.JSON(200, oauth.CreateJwksResponseObject(pubKey))
}
```

## Usage

Once you have completed the prerequisites, you can implement and use the client.

### Create a new OAuth Client

Create an OAuth client by calling `oauth.NewClient`

```go
clientId := "https://yourdomain.com/path/to/client-metadata.json"
callbackUrl := "https://yourdomain.com/oauth-callback"

b, err := os.ReadFile("./jwks.json")
if err != nil {
    return err
}

k, err := oauth.ParseJWKFromBytes(b)
if err != nil {
    return err
}

cli, err := oauth.NewClient(oauth.ClientArgs{
    ClientJwk: k,
    ClientId: clientId,
    RedirectUri: callbackUrl,
})
if err != nil {
    return err
}
```

### Starting Authenticating

There are examples of the authentication flow inside of `cmd/client_tester/handle_auth.go`, however we'll talk about some general points here.

#### Determining the user's PDS

You should allow for users to input their handle, DID, or PDS URL when detemrining where to send the user for authentication. An example that covers all the bases of what you'll need to do is when a user uses their handle.

```go
cli := oauth.NewClient()
userInput := "hailey.at"

// If you already have a did or a URL, you can skip this step
did, err := resolveHandle(ctx, userInput) // returns did:plc:abc123 or did:web:test.com
if err != nil {
    return err
}

// If you already have a URL, you can skip this step
service, err := resolveService(ctx, did) // returns https://pds.haileyok.com
if err != nil {
    return err
}

authserver, err := cli.ResolvePdsAuthServer(ctx, service)
if err != nil {
    return err
}

authmeta, err := cli.FetchAuthServerMetadata(ctx, authserver)
if err != nil {
    return err
}
```

By this point, you will have the necessary information to direct the user where they need to go.

#### Create a private DPoP JWK for the user

You'll need to create a private DPoP JWK for the user before directing them to their PDS to authenticate. You'll need to store this in a later step, and you will need to pass it along inside the PAR request, so go ahead and marshal it as well. 

```go
k, err := oauth.GenerateKey(nil)
if err != nil {
    return err
}

b, err := json.Marshal(k)
if err != nil {
    return err
}
```

#### Make the PAR request

```go
// Note: the login hint - here `handle` - should only be set if you have a DID or handle. Leave it empty if all you
// have is the PDS url.
parResp, err := cli.SendParAuthRequest(ctx, authserver, authmeta, handle, scope, dpopPrivateKey)
if err != nil {
    return err
}
```

#### Store the needed information before redirecting

Some items will need to be stored for later when the PDS redirects to your application.

- The user's DID, if you have it
- The user's PDS url
- The authserver issuer
- The `state` value from the PAR request
- The PKCE verifier from the PAR  rquest
- The DPoP autherserver nonce from the PAR request
- The DPoP private JWK thhat you generated

It is up to you how you want to store these values. Most likely, you will want to store them in a database. You may also want to store the `state` variable in the user's session _as well as the database_ so you can verify it later. There's a basic implementation inside of `cmd/client_tester/handle_auth.go`.

#### Redirect

Once you've stored the needed info, send the user to their PDS. The URL to redirect the user to should have both the `client_id` and `request_uri` `GET` parameters set.

```go
u, _ := url.Parse(meta.AuthorizationEndpoint)
u.RawQuery = fmt.Sprintf("client_id=%s&requires_uri=%s", url.QueryEscape(yourClientId), parResp.RequestUri)

// Redirect the user to created url
```

### Callback handling

Handling the response is pretty easy, though you'll want to check a few things once you receive the response.

- Ensure that `state`, `iss`, and `code` are present in the `GET` parameters
- Ensure that the `state` value matches the `state` value you stored before redirection

You'll next need to load all of the request information you previously stored. Once you have that information, you can perform the initial token request.

```go
resCode := e.QueryParam("code")
resIss := e.QueryParam("iss")

itResp, err := cli.InitialTokenRequest(ctx, resCode, resIss, requestInfo.PkceVerifier, requestInfo.DpopAuthserverNonce, requestInfo.privateJwk)
if err != nil {
    return err
}
```

#### Final checks

Finally, check that the scope received matches the requested scope. Also, if you didn't  have the user's DID before redirecting earlier, you can now get their DID from `itResp.Sub`.

```go
if itResp.Scope != requestedScope {
    return fmt.Errorf("bad scope")
}

if requestInfo.Did == "" {
    // Do something...
}
```

#### Store the response

Now, you can store the response items to make make authenticated requests later. You likely will want to store at least the user's DID in a secure session so that you know who the user is.

### Refreshing the token

The acess token you receive will expire after one hour and you will need to refresh it. You may choose to create a helper method that will refresh the token as necessary whenever you fetch the authentication information from your store. For an example, see `cmd/client_test/user.go`.

## Making requests

You may have some experience using the atproto SDK's helper methods from `indigo`. For example, you may be able to call `ActorGetProfile()` to fetch a user's profile. Currently, the atproto SDK does not support OAuth however, and will need some
changes. In the meantime, I have added a custom XRPC client to this repo that can be used with OAuth sessions created in this library.

### Creating an XRPC client

Similar to the `indigo/xrpc` package, you can create an XRPC client like so

```go
client := &oauth.XrpcClient{
    OnDpopPdsNonceChanged: func(did, newNonce string) {
	// Handle updating your store with the new nonce
    },
}
```

The `OnDpopPdsNonceChanged` callback will fire whenever an authenticated request results in an updated DPoP PDS nonce. You should update your store with this nonce for future requests.

### Making requests

Instead of using "helpers", for now you should make requests by simply calling `Do()` on the XRPC client. You will need to pass `XrpcAuthedRequestArgs` to the function to perform authenticated requests.
If the parameter is `nil`, the request will be made unauthenticated. A few examples are below.

#### Creating authentication arguments

```go
// Get your user's session - however you are doing that - and retrieve their did

// Grab the oauth session from your database
oauthSession, err := s.getOauthSession(e.Request().Context(), did)

// Parse the user's JWK to pass into arguments
privateJwk, err := oauth.ParseJWKFromBytes([]byte(oauthSession.DpopPrivateJwk))
if err != nil {
	return nil, false, err
}

return &oauth.XrpcAuthedRequestArgs{
	Did:            oauthSession.Did,
	AccessToken:    oauthSession.AccessToken,
	PdsUrl:         oauthSession.PdsUrl,
	Issuer:         oauthSession.AuthserverIss,
	DpopPdsNonce:   oauthSession.DpopPdsNonce,
	DpopPrivateJwk: privateJwk,
}, nil
```

#### Making a post

```go
authArgs, err := s.getOauthSessionAuthArgs(e)
if err != nil {
	return err
}

post := bsky.FeedPost{
	Text:      "hello from atproto golang oauth client",
	CreatedAt: syntax.DatetimeNow().String(),
}

input := atproto.RepoCreateRecord_Input{
	Collection: "app.bsky.feed.post",
	Repo:       authArgs.Did,
	Record:     &util.LexiconTypeDecoder{Val: &post},
}

var out atproto.RepoCreateRecord_Output
if err := s.xrpcCli.Do(e.Request().Context(), authArgs, xrpc.Procedure, "application/json", "com.atproto.repo.createRecord", nil, input, &out); err != nil {
	return err
}
```

#### Getting a profile

```go
authArgs, err := s.getOauthSessionAuthArgs(e)
if err != nil {
	return err
}

var out bsky.ActorDefs_ProfileViewDetailed
if err := s.xrpcCli.Do(e.Request().Context(), authArgs, xrpc.Query, "", "app.bsky.actor.getProfile", map[string]any{"actor": authArgs.Did}, nil, &out); err != nil {
	return err
}
```
