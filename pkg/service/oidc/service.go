package oidc

import (
	"context"
	"crypto/rand"
	"net/http"
	"time"

	didsdk "github.com/TBD54566975/ssi-sdk/did"
	"github.com/TBD54566975/ssi-sdk/oidc/issuance"
	"github.com/TBD54566975/ssi-sdk/util"
	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/pkg/errors"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"github.com/sirupsen/logrus"
	credint "github.com/tbd54566975/ssi-service/internal/credential"
	"github.com/tbd54566975/ssi-service/internal/did"
	"github.com/tbd54566975/ssi-service/internal/keyaccess"
	"github.com/tbd54566975/ssi-service/pkg/server/framework"
	"github.com/tbd54566975/ssi-service/pkg/service/credential"
	svcframework "github.com/tbd54566975/ssi-service/pkg/service/framework"
	"github.com/tbd54566975/ssi-service/pkg/service/oidc/model"
)

const DefaultCNonceExpiration = 5 * time.Second

type Service struct {
	// key to use for generating nonce values.
	key             *otp.Key
	cNonceExpiresIn time.Duration

	resolver    didsdk.Resolver
	credService *credential.Service
}

var _ svcframework.Service = (*Service)(nil)

func (s Service) Type() svcframework.Type {
	return svcframework.OIDC
}

func (s Service) Status() svcframework.Status {
	return svcframework.Status{Status: svcframework.StatusReady}
}

type Option func(*Service)

func WithCNonceExpiresIn(d time.Duration) Option {
	return func(service *Service) {
		service.cNonceExpiresIn = d
	}
}

func WithOTPKey(k *otp.Key) Option {
	return func(service *Service) {
		service.key = k
	}
}

func NewOIDCService(didResolver didsdk.Resolver, service *credential.Service, serviceKey [32]byte, opts ...Option) *Service {
	s := &Service{
		cNonceExpiresIn: DefaultCNonceExpiration,
		resolver:        didResolver,
		credService:     service,
	}
	for _, o := range opts {
		o(s)
	}
	if s.key == nil {
		key, err := totp.Generate(totp.GenerateOpts{
			Issuer:      "ssi-service",
			AccountName: "internal",
			Period:      uint(s.cNonceExpiresIn / time.Second),
			SecretSize:  32,
			Digits:      16,
			Rand:        rand.Reader,
			Algorithm:   otp.AlgorithmSHA512,
			Secret:      serviceKey[:],
		})
		if err != nil {
			panic(err)
		}
		WithOTPKey(key)(s)
	}

	return s
}

func (s Service) CredentialEndpoint(ctx context.Context, credRequest *model.CredentialRequest) (*model.CredentialResponse, error) {
	if credRequest.Format == "" {
		return nil, framework.NewRequestErrorMsg("invalid_request", http.StatusBadRequest)
	}
	if credRequest.Format != issuance.JWTVCJSON {
		return nil, framework.NewRequestErrorMsg("unsupported_credential_format", http.StatusBadRequest)
	}
	if credRequest.Proof == nil {
		return nil, errors.New("proof is required")
	}

	var subject string
	var err error
	switch credRequest.Proof.ProofType {
	case "jwt":
		subject, err = s.processProof(ctx, credRequest.Proof)
		if err != nil {
			return nil, errors.Wrap(err, "processing proof")
		}
	default:
		return nil, errors.New("proof_type not recognized")
	}

	serviceResp, err := s.credService.GetCredentialsBySubject(ctx, credential.GetCredentialBySubjectRequest{Subject: subject})
	if err != nil {
		return nil, err
	}

	toIssue, err := findCredentialToIssue(serviceResp, credRequest)
	if err != nil {
		return nil, errors.Wrap(err, "finding credentials")
	}

	const DefaultDuration = 120 * time.Second

	return &model.CredentialResponse{
		Format:          string(credRequest.Format),
		Credential:      string(*toIssue.CredentialJWT),
		CNonce:          uuid.NewString(),
		CNonceExpiresIn: int(DefaultDuration / time.Second),
	}, nil
}

func findCredentialToIssue(serviceResp *credential.GetCredentialsResponse, credRequest *model.CredentialRequest) (*credint.Container, error) {
	for _, c := range serviceResp.Credentials {
		types, err := util.InterfaceToStrings(c.Credential.Type)
		if err != nil {
			return nil, errors.Wrap(err, "converting interfaces to strings")
		}
		if sameElements(types, credRequest.Types) {
			return &c, nil
		}
	}
	return nil, errors.New("no credential found")
}

func sameElements(arr1, arr2 []string) bool {
	if len(arr1) != len(arr2) {
		return false
	}

	// Create a map to count the frequency of each element in arr1
	count := make(map[string]int)
	for _, s := range arr1 {
		count[s]++
	}

	// Check if each element in arr2 exists in the count map
	for _, s := range arr2 {
		if count[s] == 0 {
			return false
		}
		count[s]--
	}

	return true
}

var (
	ErrNonceNotPresent = errors.New("nonce not present in token")
	ErrNonceNotString  = errors.New("nonce should be a string")
	ErrNonceDifferent  = errors.New("nonce different from expected")
)

func (s Service) processProof(ctx context.Context, proof *model.ProofParameter) (string, error) {
	// The Credential Issuer MUST validate that the proof is actually signed by a key identified in the JOSE Header
	message, err := jws.ParseString(proof.JWT)
	if err != nil {
		return "", errors.Wrap(err, "parsing JWT")
	}

	if len(message.Signatures()) != 1 {
		return "", errors.New("jwt expected to have exactly one signature")
	}
	headers := message.Signatures()[0].ProtectedHeaders()

	// - typ: REQUIRED. MUST be openid4vci-proof+jwt, which explicitly types the proof JWT as recommended in Section 3.11 of [RFC8725].
	const openID4VCIType = "openid4vci-proof+jwt"
	if headers.Type() != openID4VCIType {
		return "", errors.Errorf("typ must be set to %q", openID4VCIType)
	}
	// - alg: REQUIRED. A digital signature algorithm identifier such as per IANA "JSON Web Signature and Encryption Algorithms" registry. MUST NOT be none or an identifier for a symmetric algorithm (MAC).
	allowedAlgs := map[jwa.SignatureAlgorithm]struct{}{
		jwa.ES256:  {},
		jwa.ES256K: {},
		jwa.ES384:  {},
		jwa.ES512:  {},
		jwa.EdDSA:  {},
		jwa.PS256:  {},
		jwa.PS384:  {},
		jwa.PS512:  {},
		jwa.RS256:  {},
		jwa.RS384:  {},
		jwa.RS512:  {},
	}
	alg, ok := allowedAlgs[headers.Algorithm()]
	if !ok {
		return "", errors.Errorf("alg %q is not allowed", alg)
	}

	// Only one of kid, jwk, or x5c can be present.
	kid := headers.KeyID()
	headerJWK := headers.JWK()
	certChain := headers.X509CertChain()

	if !((kid != "") != (headerJWK != nil) != (certChain != nil)) {
		return "", errors.New("exactly one of kid, jwk, or x5c must be present")
	}

	// We'll do verification later, once we've established that the nonce is one we produced.
	token, err := jwt.ParseString(proof.JWT, jwt.WithVerify(false))
	if err != nil {
		return "", errors.Wrap(err, "parsing jwt")
	}

	nonceRaw, ok := token.Get("nonce")
	if !ok {
		return "", ErrNonceNotPresent
	}
	nonce, ok := nonceRaw.(string)
	if !ok {
		return "", ErrNonceNotString
	}
	if !s.isNonceValid(nonce) {
		return "", ErrNonceDifferent
	}

	if kid != "" {
		// - kid: CONDITIONAL. JOSE Header containing the key ID. If the Credential shall be bound to a DID, the kid refers
		// to a DID URL which identifies a particular key in the DID Document that the Credential shall be bound to.
		// MUST NOT be present if jwk or x5c is present.

		if err := did.VerifyTokenFromDID(ctx, s.resolver, kid, keyaccess.JWT(proof.JWT)); err != nil {
			return "", errors.Wrap(err, "verifying")
		}
		return kid, nil
	}

	if headerJWK != nil {
		// - jwk: CONDITIONAL. JOSE Header containing the key material the new Credential shall be bound to. MUST NOT be
		// present if kid or x5c is present.
		return "", util.NotImplementedError
	}

	if certChain != nil {
		// - x5c: CONDITIONAL. JOSE Header containing a certificate or certificate chain corresponding to the key used to
		// sign the JWT. This element MAY be used to convey a key attestation. In such a case, the actual key certificate
		// will contain attributes related to the key properties. MUST NOT be present if kid or jwk is present.
		return "", util.NotImplementedError
	}

	// The Credential Issuer MUST validate that the proof is actually signed by a key identified in the JOSE Header.
	return "", errors.New("unreachable")
}

func (s Service) isNonceValid(nonce string) bool {
	valid, err := totp.ValidateCustom(nonce, s.key.Secret(), time.Now(), s.validateOpts())
	if err != nil {
		logrus.WithError(err).Error("Problem validating")
	}
	return valid
}

// CurrentNonce returns a time based one time password as defined in RFC 6238. It is meant to be used
func (s Service) CurrentNonce() (string, error) {
	passcode, err := totp.GenerateCodeCustom(s.key.Secret(), time.Now(), s.validateOpts())
	if err != nil {
		return "", errors.Wrap(err, "generating code")
	}
	return passcode, nil
}

// NonceExpiresIn returns the number of seconds until the current nonce expires.
func (s Service) NonceExpiresIn() int {
	return int(s.cNonceExpiresIn / time.Second)
}

func (s Service) validateOpts() totp.ValidateOpts {
	return totp.ValidateOpts{
		Period:    uint(s.key.Period()),
		Digits:    16,
		Algorithm: s.key.Algorithm(),
	}
}
