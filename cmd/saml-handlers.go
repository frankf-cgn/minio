package cmd

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/crewjam/saml"
	"github.com/dgrijalva/jwt-go"
	jwtreq "github.com/dgrijalva/jwt-go/request"
)

// SAMLMiddleware implements middleware than allows a web application
// to support SAML.
//
// It implements http.Handler so that it can provide the metadata and ACS endpoints,
// typically /SAML2/Meta and /SAML2/ACS, respectively.
//
// It also provides middleware, RequireAccount which redirects users to
// the auth process if they do not have session credentials.
//
// When redirecting the user through the SAML auth flow, the middlware assigns
// a temporary cookie with a random name beginning with "saml_". The value of
// the cookie is a signed JSON Web Token containing the original URL requested
// and the SAML request ID. The random part of the name corresponds to the
// RelayState parameter passed through the SAML flow.
//
// When validating the SAML response, the RelayState is used to look up the
// correct cookie, validate that the SAML request ID, and redirect the user
// back to their original URL.
//
// Sessions are established by issuing a JSON Web Token (JWT) as a session
// cookie once the SAML flow has succeeded. The JWT token contains the
// authenticated attributes from the SAML assertion.
//
// When the middlware receives a request with a valid session JWT it extracts
// the SAML attributes and modifies the http.Request object adding headers
// corresponding to the specified attributes. For example, if the attribute
// "cn" were present in the initial assertion with a value of "Alice Smith",
// then a corresponding header "X-Saml-Cn" will be added to the request with
// a value of "Alice Smith". For safety, the middleware strips out any existing
// headers that begin with "X-Saml-".
//
// When issuing JSON Web Tokens, a signing key is required. Because the
// SAML service provider already has a private key, we borrow that key
// to sign the JWTs as well.
type SAMLMiddleware struct {
	ServiceProvider   saml.ServiceProvider
	AllowIDPInitiated bool
	CookieName        string
	CookieMaxAge      time.Duration
}

var jwtSigningMethod = jwt.SigningMethodHS512

func randomBytes(n int) []byte {
	rv := make([]byte, n)
	if _, err := saml.RandReader.Read(rv); err != nil {
		panic(err)
	}
	return rv
}

// SAMLMetadataHandler - implements http.Handler and serves the SAML
// Metadata specific HTTP endpoint URI.
func (m *SAMLMiddleware) SAMLMetadataHandler(w http.ResponseWriter, r *http.Request) {
	buf, err := xml.MarshalIndent(m.ServiceProvider.Metadata(), "", "  ")
	if err != nil {
		errorIf(err, "Unable to marshal XML")
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/samlmetadata+xml")
	w.Write(buf)
}

// SAMLAssertionConsumerHandler - implements http.Handler and serves the SAML
// Assertion Consumer specific HTTP endpoint URI.
func (m *SAMLMiddleware) SAMLAssertionConsumerHandler(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		errorIf(err, "Unable to parse assertion form")
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}
	assertion, err := m.ServiceProvider.ParseResponse(r, m.getPossibleRequestIDs(r))
	if err != nil {
		switch perr := err.(type) {
		case *saml.InvalidResponseError:
			errorIf(perr.PrivateErr, "Unable to parse SAML response")
		default:
			errorIf(err, "Unable to parse SAML response")
		}
		http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
		return
	}
	m.Authorize(w, r, assertion)
}

// SAMLLogoutHandler is SAML logout http.Handler - that logs you out.
func (m *SAMLMiddleware) SAMLLogoutHandler(w http.ResponseWriter, r *http.Request) {
	if !isSAMLAuthorized(r, defaultCookieName, m.ServiceProvider) {
		return
	}
	// If we try to redirect when the original request is the ACS URL we'll
	// end up in a loop. This is a programming error, so we panic here. In
	// general this means a 500 to the user, which is preferable to a
	// redirect loop.
	if r.URL.Path == m.ServiceProvider.AcsURL.Path {
		http.Error(w, "Cannot call this directly on ACS URL path", http.StatusInternalServerError)
		return
	}
}

// SAMLLoginHandler is SAML login http.Handler - that logs you in.
// associated with a valid session. If the request is not associated with a valid
// session, then rather than serve the request, the middlware redirects the user
// to start the SAML auth flow.
func (m *SAMLMiddleware) SAMLLoginHandler(w http.ResponseWriter, r *http.Request) {
	if isSAMLAuthorized(r, defaultCookieName, m.ServiceProvider) {
		cookie, _ := r.Cookie(defaultCookieName)
		if cookie != nil {
			w.Write([]byte(`<script src="https://unpkg.com/local-storage-fallback/lib/dist.min.js"></script>`))
			w.Write([]byte(`<script>`))
			w.Write([]byte(fmt.Sprintf(`window.localStorageFallback.setItem('token', '%s')`, cookie.Value)))
			w.Write([]byte(`</script>`))
		}
		return
	}

	// If we try to redirect when the original request is the ACS URL we'll
	// end up in a loop. This is a programming error, so we panic here. In
	// general this means a 500 to the user, which is preferable to a
	// redirect loop.
	if r.URL.Path == m.ServiceProvider.AcsURL.Path {
		http.Error(w, "Cannot call this directly on ACS URL path", http.StatusInternalServerError)
		return
	}

	binding := saml.HTTPRedirectBinding
	bindingLocation := m.ServiceProvider.GetSSOBindingLocation(binding)
	if bindingLocation == "" {
		binding = saml.HTTPPostBinding
		bindingLocation = m.ServiceProvider.GetSSOBindingLocation(binding)
	}

	req, err := m.ServiceProvider.MakeAuthenticationRequest(bindingLocation)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// relayState is limited to 80 bytes but also must be integrety protected.
	// this means that we cannot use a JWT because it is way to long. Instead
	// we set a cookie that corresponds to the state
	relayState := base64.URLEncoding.EncodeToString(randomBytes(42))

	secretBlock := x509.MarshalPKCS1PrivateKey(m.ServiceProvider.Key)
	state := jwt.New(jwtSigningMethod)
	claims := state.Claims.(jwt.MapClaims)
	claims["id"] = req.ID
	claims["uri"] = r.URL.String()
	signedState, err := state.SignedString(secretBlock)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	cookie := &http.Cookie{
		Name:     fmt.Sprintf("saml_%s", relayState),
		Value:    signedState,
		MaxAge:   int(saml.MaxIssueDelay.Seconds()),
		Secure:   true,
		HttpOnly: false,
		Path:     m.ServiceProvider.AcsURL.Path,
	}
	http.SetCookie(w, cookie)

	if binding == saml.HTTPRedirectBinding {
		http.Redirect(w, r, req.Redirect(relayState).String(), http.StatusFound)
		return
	} // else saml.HTTPPostBinding

	if binding == saml.HTTPPostBinding {
		w.Header().Set("Content-Security-Policy", ""+
			"default-src; "+
			"script-src 'sha256-D8xB+y+rJ90RmLdP72xBqEEc0NUatn7yuCND0orkrgk='; "+
			"reflected-xss block; "+
			"referrer no-referrer;")
		w.Header().Add("Content-type", "text/html")
		w.Write([]byte(`<!DOCTYPE html><html><body>`))
		w.Write(req.Post(relayState))
		w.Write([]byte(`</body></html>`))
		return
	}
	panic("not reached")
}

func (m *SAMLMiddleware) getPossibleRequestIDs(r *http.Request) []string {
	rv := []string{}
	for _, cookie := range r.Cookies() {
		if !strings.HasPrefix(cookie.Name, "saml_") {
			continue
		}
		jwtParser := jwt.Parser{
			ValidMethods: []string{jwtSigningMethod.Name},
		}
		token, err := jwtParser.Parse(cookie.Value, func(t *jwt.Token) (interface{}, error) {
			secretBlock := x509.MarshalPKCS1PrivateKey(m.ServiceProvider.Key)
			return secretBlock, nil
		})
		if err != nil || !token.Valid {
			errorIf(err, "Invalid token")
			continue
		}
		claims := token.Claims.(jwt.MapClaims)
		rv = append(rv, claims["id"].(string))
	}

	// If IDP initiated requests are allowed, then we can expect an empty response ID.
	if m.AllowIDPInitiated {
		rv = append(rv, "")
	}

	return rv
}

// TokenClaims - extends jwt standard claims with SAML attributes.
type TokenClaims struct {
	jwt.StandardClaims
	Attributes map[string][]string `json:"attr"`
}

// Authorize is invoked by ServeHTTP when we have a new, valid SAML assertion.
// It sets a cookie that contains a signed JWT containing the assertion attributes.
// It then redirects the user's browser to the original URL contained in RelayState.
func (m *SAMLMiddleware) Authorize(w http.ResponseWriter, r *http.Request, assertion *saml.Assertion) {
	secretBlock := x509.MarshalPKCS1PrivateKey(m.ServiceProvider.Key)

	redirectURI := "/"
	if r.Form.Get("RelayState") != "" {
		stateCookie, err := r.Cookie(fmt.Sprintf("saml_%s", r.Form.Get("RelayState")))
		if err != nil {
			errorIf(err, "Cannot find the corresponding cookied %s", fmt.Sprintf("saml_%s", r.Form.Get("RelayState")))
			http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
			return
		}

		jwtParser := jwt.Parser{
			ValidMethods: []string{jwtSigningMethod.Name},
		}
		state, err := jwtParser.Parse(stateCookie.Value, func(t *jwt.Token) (interface{}, error) {
			return secretBlock, nil
		})
		if err != nil || !state.Valid {
			errorIf(err, "Cannot decode stat eJWT: %s (%s", err, stateCookie.Value)
			http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
			return
		}

		claims := state.Claims.(jwt.MapClaims)
		redirectURI = claims["uri"].(string)

		// delete the cookie
		stateCookie.Value = ""
		stateCookie.Expires = time.Unix(1, 0) // past time as close to epoch as possible, but not zero time.Time{}
		http.SetCookie(w, stateCookie)
	}

	now := saml.TimeNow()
	claims := TokenClaims{
		StandardClaims: jwt.StandardClaims{
			Audience:  m.ServiceProvider.Metadata().EntityID,
			IssuedAt:  assertion.IssueInstant.Unix(),
			ExpiresAt: now.Add(m.CookieMaxAge).Unix(),
			NotBefore: now.Unix(),
		},
	}
	if sub := assertion.Subject; sub != nil {
		if nameID := sub.NameID; nameID != nil {
			claims.StandardClaims.Subject = nameID.Value
		}
	}
	for _, attributeStatement := range assertion.AttributeStatements {
		claims.Attributes = map[string][]string{}
		for _, attr := range attributeStatement.Attributes {
			claimName := attr.FriendlyName
			if claimName == "" {
				claimName = attr.Name
			}
			for _, value := range attr.Values {
				claims.Attributes[claimName] = append(claims.Attributes[claimName], value.Value)
			}
		}
	}

	cred, err := getNewCredentialWithExpiration(now.Add(defaultCookieMaxAge))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Set the newly generated credentials.
	globalServerCreds.SetCredential(cred)

	// Save newly generated credentials to disk.
	if err = globalServerCreds.Save(); err != nil {
		errorIf(err, "Unable to save STS credentials")
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	tokenStr, err := jwt.NewWithClaims(jwtSigningMethod, claims).SignedString([]byte(cred.SecretKey))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	authToken := canonicalAuth(cred.AccessKey, tokenStr)
	http.SetCookie(w, &http.Cookie{
		Name:     defaultCookieName,
		Value:    authToken,
		MaxAge:   int(defaultCookieMaxAge.Seconds()),
		Secure:   true,
		HttpOnly: false,
		Path:     "/",
	})

	http.Redirect(w, r, redirectURI, http.StatusFound)
}

func parseSAMLJWT(auth string) (token *jwt.Token, tokenClaims TokenClaims, err error) {
	accessKey, tokenStr := extractAccessAndJWT(auth)
	if tokenStr == "" {
		return nil, tokenClaims, jwtreq.ErrNoTokenInRequest
	}
	token, err = jwt.ParseWithClaims(tokenStr, &tokenClaims, func(jwtToken *jwt.Token) (interface{}, error) {
		if _, ok := jwtToken.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", jwtToken.Header["alg"])
		}
		if accessKey != "" {
			cred := globalServerCreds.GetCredential(accessKey)
			if cred.IsExpired() {
				return nil, errInvalidAccessKeyID
			}
			if cred.AccessKey != accessKey {
				return nil, errInvalidAccessKeyID
			}
			return []byte(cred.SecretKey), nil
		}
		return []byte(serverConfig.GetCredential().SecretKey), nil
	})
	return token, tokenClaims, err
}

// isSAMLAuthorized is invoked by RequireAccount to determine if the request
// is already authorized or if the user's browser should be redirected to the
// SAML login flow. If the request is authorized, then the request headers
// starting with X-Saml- for each SAML assertion attribute are set. For example,
// if an attribute "uid" has the value "alice@example.com", then the following
// header would be added to the request:
//
//     X-Saml-Uid: alice@example.com
//
// It is an error for this function to be invoked with a request containing
// any headers starting with X-Saml. This function will panic if you do.
func isSAMLAuthorized(r *http.Request, cookieName string, sp saml.ServiceProvider) bool {
	cookie, err := r.Cookie(cookieName)
	if err != nil {
		return false
	}

	token, tokenClaims, err := parseSAMLJWT(cookie.Value)
	if err != nil || !token.Valid {
		errorIf(err, "Invalid token")
		return false
	}
	if err = tokenClaims.StandardClaims.Valid(); err != nil {
		errorIf(err, "Invalid token claims")
		return false
	}
	if tokenClaims.Audience != sp.Metadata().EntityID {
		errorIf(err, "Invalid audience")
		return false
	}

	// It is an error for the request to include any X-SAML* headers,
	// because those might be confused with ours. If we encounter any
	// such headers, we abort the request, so there is no confustion.
	for headerName := range r.Header {
		if strings.HasPrefix(headerName, "X-Saml") {
			panic("X-Saml-* headers should not exist when this function is called")
		}
	}

	for claimName, claimValues := range tokenClaims.Attributes {
		for _, claimValue := range claimValues {
			r.Header.Add("X-Saml-"+claimName, claimValue)
		}
	}
	r.Header.Set("X-Saml-Subject", tokenClaims.Subject)

	return true
}
