package authorizationserver

import (
	"context"
	"fmt"
	"net/http"

	"github.com/TBD54566975/ssi-sdk/oidc/issuance"
	"github.com/goccy/go-json"
	"github.com/ory/fosite"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"

	"github.com/tbd54566975/ssi-service/pkg/authorizationserver/request"
)

type AuthService struct {
	issuerMetadata *issuance.IssuerMetadata
	provider       fosite.OAuth2Provider
}

func NewAuthService(issuerMetadata *issuance.IssuerMetadata, provider fosite.OAuth2Provider) *AuthService {
	return &AuthService{issuerMetadata: issuerMetadata, provider: provider}
}

// AuthEndpoint is a Handler that implements https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-authorization-endpoint
func (s AuthService) AuthEndpoint(ctx context.Context, rw http.ResponseWriter, req *http.Request) error {
	ar, err := s.provider.NewAuthorizeRequest(ctx, req)
	if err != nil {
		logrus.WithError(err).Error("failed NewAuthorizeRequest")
		s.provider.WriteAuthorizeError(ctx, rw, ar, err)
		return nil
	}

	authorizationDetailsJSON := ar.GetRequestForm().Get("authorization_details")
	var authorizationDetails request.AuthorizationDetails
	if err := json.Unmarshal([]byte(authorizationDetailsJSON), &authorizationDetails); err != nil {
		logrus.WithError(err).Error("failed Unmarshal")
		s.provider.WriteAuthorizeError(ctx, rw, ar, err)
		return nil
	}

	if err := authorizationDetails.IsValid(); err != nil {
		logrus.WithError(err).Error("failed Unmarshal")
		s.provider.WriteAuthorizeError(ctx, rw, ar, err)
		return nil
	}

	// If the Credential IssuerDID metadata contains an authorization_server parameter, the authorization detail's
	// locations common data field MUST be set to the Credential IssuerDID Identifier value
	if s.issuerMetadata.AuthorizationServer != nil {
		for i, d := range authorizationDetails {
			switch d.Type {
			case "openid_credential":
				if err := s.processOpenIDCredential(d); err != nil {
					logrus.WithError(err).Error("failed processing openid_credential")
					s.provider.WriteAuthorizeError(ctx, rw, ar, err)
					return nil
				}
				// TODO(https://github.com/TBD54566975/ssi-service/issues/368): support dynamic auth request

			default:
				err := errors.Errorf("the value of authorization_details[%d].type found was %q, which is not recognized", i, d.Type)
				logrus.WithError(err).Error("unrecognized type")
				s.provider.WriteAuthorizeError(ctx, rw, ar, err)
				return nil
			}
		}
	}

	// You have now access to authorizeRequest, Code ResponseTypes, Scopes ...
	var requestedScopes string
	for _, this := range ar.GetRequestedScopes() {
		requestedScopes += fmt.Sprintf(`<li><input type="checkbox" name="scopes" value="%s">%s</li>`, this, this)
	}

	// Normally, this would be the place where you would check if the user is logged in and gives his consent.
	// We're simplifying things and just checking if the request includes a valid username and password
	if err := req.ParseForm(); err != nil {
		logrus.WithError(err).Error("failed parsing request form")
		s.provider.WriteAuthorizeError(ctx, rw, ar, err)
		return nil
	}
	if req.PostForm.Get("username") != "peter" {
		rw.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = rw.Write([]byte(`<h1>Login page</h1>`))
		_, _ = rw.Write([]byte(fmt.Sprintf(`
			<p>Howdy! This is the log in page. For this example, it is enough to supply the username.</p>
			<form method="post">
				<p>
					By logging in, you consent to grant these scopes:
					<ul>%s</ul>
				</p>
				<input type="text" name="username" /> <small>try peter</small><br>
				<input type="submit">
			</form>
		`, requestedScopes)))
		return nil
	}

	// let's see what scopes the user gave consent to
	for _, scope := range req.PostForm["scopes"] {
		ar.GrantScope(scope)
	}

	// Now that the user is authorized, we set up a session:
	mySessionData := newSession("peter")

	// When using the HMACSHA strategy you must use something that implements the HMACSessionContainer.
	// It brings you the power of overriding the default values.
	//
	// mySessionData.HMACSession = &strategy.HMACSession{
	//	AccessTokenExpiry: time.Now().Add(time.Day),
	//	AuthorizeCodeExpiry: time.Now().Add(time.Day),
	// }
	//

	// If you're using the JWT strategy, there's currently no distinction between access token and authorize code claims.
	// Therefore, you both access token and authorize code will have the same "exp" claim. If this is something you
	// need let us know on github.
	//
	// mySessionData.JWTClaims.ExpiresAt = time.Now().Add(time.Day)

	// It's also wise to check the requested scopes, e.g.:
	// if ar.GetRequestedScopes().Has("admin") {
	//     http.Error(rw, "you're not allowed to do that", http.StatusForbidden)
	//     return
	// }

	// Now we need to get a response. This is the place where the AuthorizeEndpointHandlers kick in and start processing the request.
	// NewAuthorizeResponse is capable of running multiple response type handlers which in turn enables this library
	// to support open id connect.
	response, err := s.provider.NewAuthorizeResponse(ctx, ar, mySessionData)

	// Catch any errors, e.g.:
	// * unknown client
	// * invalid redirect
	// * ...
	if err != nil {
		logrus.WithError(err).Error("failed NewAuthorizeResponse")
		s.provider.WriteAuthorizeError(ctx, rw, ar, err)
		return nil
	}

	// Last but not least, send the response!
	s.provider.WriteAuthorizeResponse(ctx, rw, ar, response)
	return nil
}

func (s AuthService) processOpenIDCredential(d request.AuthorizationDetail) error {
	if len(d.Locations) != 1 {
		return errors.New("locations expected to have a single element")
	}
	if d.Locations[0] != s.issuerMetadata.CredentialIssuer.String() {
		return errors.Errorf(
			"locations[0] expected to be equal to %q, but received %q",
			s.issuerMetadata.CredentialIssuer.String(),
			d.Locations[0],
		)
	}
	return nil
}
