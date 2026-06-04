package api

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

type oidcTokenVerifier struct {
	issuer       string
	clientID     string
	jwksURL      string
	subjectClaim string
	groupsClaim  string
	adminUsers   map[string]bool
	adminGroups  map[string]bool

	mu         sync.Mutex
	keys       map[string]*rsa.PublicKey
	keysUntil  time.Time
	httpClient *http.Client
	now        func() time.Time
}

type oidcIdentity struct {
	User     string
	Groups   []string
	Subjects []string
	Admin    bool
}

type oidcJWTHeader struct {
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	Typ string `json:"typ"`
}

type oidcJWTClaims struct {
	Issuer    string          `json:"iss"`
	Subject   string          `json:"sub"`
	Audience  json.RawMessage `json:"aud"`
	ExpiresAt int64           `json:"exp"`
	NotBefore int64           `json:"nbf,omitempty"`
	IssuedAt  int64           `json:"iat,omitempty"`
	raw       map[string]any
}

type oidcJWKS struct {
	Keys []oidcJWK `json:"keys"`
}

type oidcJWK struct {
	Kty string `json:"kty"`
	Use string `json:"use"`
	Kid string `json:"kid"`
	Alg string `json:"alg"`
	N   string `json:"n"`
	E   string `json:"e"`
}

func newOIDCTokenVerifierFromEnv() *oidcTokenVerifier {
	issuer := strings.TrimRight(strings.TrimSpace(os.Getenv("BONGSU_OIDC_ISSUER")), "/")
	clientID := strings.TrimSpace(os.Getenv("BONGSU_OIDC_CLIENT_ID"))
	if issuer == "" || clientID == "" {
		return nil
	}
	jwksURL := strings.TrimSpace(os.Getenv("BONGSU_OIDC_JWKS_URL"))
	if jwksURL == "" {
		jwksURL = issuer + "/.well-known/jwks.json"
	}
	subjectClaim := strings.TrimSpace(os.Getenv("BONGSU_OIDC_SUBJECT_CLAIM"))
	if subjectClaim == "" {
		subjectClaim = "sub"
	}
	groupsClaim := strings.TrimSpace(os.Getenv("BONGSU_OIDC_GROUPS_CLAIM"))
	if groupsClaim == "" {
		groupsClaim = "groups"
	}
	return &oidcTokenVerifier{
		issuer:       issuer,
		clientID:     clientID,
		jwksURL:      jwksURL,
		subjectClaim: subjectClaim,
		groupsClaim:  groupsClaim,
		adminUsers:   mapFromList(splitCSV(os.Getenv("BONGSU_OIDC_ADMIN_USERS"))),
		adminGroups:  mapFromList(splitCSV(os.Getenv("BONGSU_OIDC_ADMIN_GROUPS"))),
		httpClient:   &http.Client{Timeout: 10 * time.Second},
		now:          time.Now,
	}
}

func (v *oidcTokenVerifier) identityFromRequest(ctx context.Context, r *http.Request) (oidcIdentity, error) {
	if v == nil {
		return oidcIdentity{}, nil
	}
	auth := strings.TrimSpace(r.Header.Get("Authorization"))
	if !strings.HasPrefix(auth, "Bearer ") {
		return oidcIdentity{}, nil
	}
	token := strings.TrimSpace(strings.TrimPrefix(auth, "Bearer "))
	if token == "" {
		return oidcIdentity{}, nil
	}
	return v.verify(ctx, token)
}

func (v *oidcTokenVerifier) verify(ctx context.Context, token string) (oidcIdentity, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return oidcIdentity{}, errors.New("invalid oidc token shape")
	}
	var header oidcJWTHeader
	if err := decodeJWTPart(parts[0], &header); err != nil {
		return oidcIdentity{}, err
	}
	if header.Alg != "RS256" || header.Kid == "" {
		return oidcIdentity{}, errors.New("unsupported oidc token header")
	}
	key, err := v.key(ctx, header.Kid)
	if err != nil {
		return oidcIdentity{}, err
	}
	signed := []byte(parts[0] + "." + parts[1])
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return oidcIdentity{}, err
	}
	digest := sha256.Sum256(signed)
	if err := rsa.VerifyPKCS1v15(key, crypto.SHA256, digest[:], sig); err != nil {
		return oidcIdentity{}, errors.New("invalid oidc token signature")
	}

	var claims oidcJWTClaims
	if err := decodeJWTPart(parts[1], &claims); err != nil {
		return oidcIdentity{}, err
	}
	claimsRaw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return oidcIdentity{}, err
	}
	if err := json.Unmarshal(claimsRaw, &claims.raw); err != nil {
		return oidcIdentity{}, err
	}
	if claims.Issuer != v.issuer {
		return oidcIdentity{}, errors.New("invalid oidc issuer")
	}
	if !claims.audienceContains(v.clientID) {
		return oidcIdentity{}, errors.New("invalid oidc audience")
	}
	now := v.now().Unix()
	if claims.ExpiresAt <= now {
		return oidcIdentity{}, errors.New("expired oidc token")
	}
	if claims.NotBefore > 0 && claims.NotBefore > now+60 {
		return oidcIdentity{}, errors.New("oidc token not yet valid")
	}
	user := claimString(claims.raw, v.subjectClaim)
	if user == "" {
		user = claims.Subject
	}
	if user == "" {
		return oidcIdentity{}, errors.New("missing oidc subject")
	}
	groups := claimStringList(claims.raw, v.groupsClaim)
	subjects := []string{"user:" + user}
	admin := v.adminUsers[user]
	for _, group := range groups {
		subjects = appendUniqueString(subjects, "group:"+group)
		if v.adminGroups[group] {
			admin = true
		}
	}
	return oidcIdentity{User: user, Groups: groups, Subjects: subjects, Admin: admin}, nil
}

func decodeJWTPart(part string, out any) error {
	raw, err := base64.RawURLEncoding.DecodeString(part)
	if err != nil {
		return err
	}
	return json.Unmarshal(raw, out)
}

func (c oidcJWTClaims) audienceContains(want string) bool {
	var one string
	if err := json.Unmarshal(c.Audience, &one); err == nil {
		return one == want
	}
	var many []string
	if err := json.Unmarshal(c.Audience, &many); err == nil {
		for _, aud := range many {
			if aud == want {
				return true
			}
		}
	}
	return false
}

func (v *oidcTokenVerifier) key(ctx context.Context, kid string) (*rsa.PublicKey, error) {
	if key := v.cachedKey(kid); key != nil {
		return key, nil
	}
	if err := v.refreshKeys(ctx); err != nil {
		return nil, err
	}
	if key := v.cachedKey(kid); key != nil {
		return key, nil
	}
	return nil, errors.New("oidc signing key not found")
}

func (v *oidcTokenVerifier) cachedKey(kid string) *rsa.PublicKey {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.keys == nil || v.now().After(v.keysUntil) {
		return nil
	}
	return v.keys[kid]
}

func (v *oidcTokenVerifier) refreshKeys(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, v.jwksURL, nil)
	if err != nil {
		return err
	}
	resp, err := v.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("oidc jwks returned HTTP %d", resp.StatusCode)
	}
	var jwks oidcJWKS
	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		return err
	}
	keys := map[string]*rsa.PublicKey{}
	for _, jwk := range jwks.Keys {
		if key, err := rsaKeyFromJWK(jwk); err == nil {
			keys[jwk.Kid] = key
		}
	}
	if len(keys) == 0 {
		return errors.New("oidc jwks contained no usable RSA keys")
	}
	v.mu.Lock()
	v.keys = keys
	v.keysUntil = v.now().Add(5 * time.Minute)
	v.mu.Unlock()
	return nil
}

func rsaKeyFromJWK(jwk oidcJWK) (*rsa.PublicKey, error) {
	if jwk.Kty != "RSA" || jwk.Kid == "" || jwk.N == "" || jwk.E == "" {
		return nil, errors.New("not an RSA signing key")
	}
	nBytes, err := base64.RawURLEncoding.DecodeString(jwk.N)
	if err != nil {
		return nil, err
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(jwk.E)
	if err != nil {
		return nil, err
	}
	e := 0
	for _, b := range eBytes {
		e = e<<8 + int(b)
	}
	if e == 0 {
		return nil, errors.New("invalid RSA exponent")
	}
	return &rsa.PublicKey{N: new(big.Int).SetBytes(nBytes), E: e}, nil
}

func claimString(raw map[string]any, name string) string {
	if name == "" {
		return ""
	}
	if v, ok := raw[name].(string); ok {
		return strings.TrimSpace(v)
	}
	return ""
}

func claimStringList(raw map[string]any, name string) []string {
	v := raw[name]
	switch typed := v.(type) {
	case string:
		return splitIdentityHeaderValues(typed)
	case []any:
		out := []string{}
		for _, item := range typed {
			if s, ok := item.(string); ok {
				out = appendUniqueString(out, s)
			}
		}
		return out
	default:
		return nil
	}
}
