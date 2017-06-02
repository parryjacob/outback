package outback

import (
	"encoding/base64"
	"net/http"

	"time"

	"encoding/json"

	log "github.com/Sirupsen/logrus"
	"github.com/parryjacob/saml"
)

type OutbackSessionProvider struct {
	oa *OutbackApp
}

type OutbackSession struct {
	ldapUser *LDAPUser
	ID       string `json:"id"`
	LDAPDN   string `json:"dn"`
	Created  int64  `json:"created"`
}

// NewSessionFromLDAP creates a new session given an LDAP user
func NewSessionFromLDAP(user *LDAPUser) *OutbackSession {
	log.WithField("dn", user.DN).Debug("creating new session for user")
	return &OutbackSession{
		ldapUser: user,
		LDAPDN:   user.DN,
		ID:       newSessionID(),
		Created:  time.Now().Unix(),
	}
}

// SAMLSession converts this OutbackSession to a saml.Session
func (os *OutbackSession) SAMLSession(oa *OutbackApp) *saml.Session {
	created := time.Unix(os.Created, 0)
	return &saml.Session{
		ID:             os.ID,
		CreateTime:     created,
		ExpireTime:     created.Add(oa.Config.CookieLifetime),
		Index:          os.ID,
		UserName:       os.ldapUser.Username,
		UserEmail:      os.ldapUser.Email,
		UserCommonName: os.ldapUser.CN,
		UserSurname:    os.ldapUser.SN,
		UserGivenName:  os.ldapUser.GivenName,
		Groups:         make([]string, 0),
		NameID:         os.ldapUser.Username,
	}
}

// Cookie returns the cookie for this session
func (os *OutbackSession) Cookie(oa *OutbackApp) *http.Cookie {
	return &http.Cookie{
		Name:     "outback_session",
		Value:    os.ID,
		MaxAge:   int(oa.Config.CookieLifetime.Seconds()),
		HttpOnly: false,
		Path:     "/",
	}
}

// SaveSession will persist the session to redis
func (os *OutbackSession) SaveSession(oa *OutbackApp) error {
	rd, err := oa.getRedis()
	if err != nil {
		return err
	}

	jsbd, err := json.Marshal(os)
	if err != nil {
		return err
	}

	return rd.Set("outback::session::"+os.ID, string(jsbd), oa.Config.CookieLifetime).Err()
}

// LoadSessionByID will attempt to load a session from JSON
func LoadSessionByID(id string, oa *OutbackApp) (*OutbackSession, error) {
	rd, err := oa.getRedis()
	if err != nil {
		return nil, err
	}

	res, err := rd.Get("outback::session::" + id).Result()
	if err != nil {
		return nil, err
	}
	if len(res) == 0 {
		return nil, nil
	}

	os := &OutbackSession{}
	err = json.Unmarshal([]byte(res), os)
	if err != nil {
		return nil, err
	}

	// populate the ldapUser
	user, err := oa.FindLDAPUserByDN(os.LDAPDN)
	if err != nil {
		return nil, err
	}
	if user == nil {
		log.WithField("dn", os.LDAPDN).Debug("tried to load session with unknown user")
		return nil, nil
	}

	os.ldapUser = user
	return os, nil
}

// GetSession returns a saml.Session or nil for the passed request
func (osp *OutbackSessionProvider) GetSession(w http.ResponseWriter, r *http.Request, req *saml.IdpAuthnRequest) *saml.Session {
	r.ParseForm()

	// Check if we're attempting to login
	if r.Method == "POST" && r.PostForm.Get("user") != "" {
		username := r.PostForm.Get("user")
		password := r.PostForm.Get("password")

		log.WithField("username", username).Debug("attempting user login")

		ldapuser, err := osp.oa.FindLDAPUser(username)
		if err != nil {
			osp.sendLoginForm(w, r, req, "Error attempting to check login!")
			log.WithError(err).WithField("username", username).Error("Failed to check for LDAP user")
			return nil
		}

		// no user
		if ldapuser == nil {
			osp.sendLoginForm(w, r, req, "Wrong username or password!")
			return nil
		}

		// user is good, check the password
		pwok, err := osp.oa.TestLDAPUserPassword(ldapuser, password)
		if err != nil {
			osp.sendLoginForm(w, r, req, "Error attempting to check password!")
			log.WithError(err).WithField("username", username).Error("Failed to check LDAP password")
			return nil
		}

		// wrong password
		if !pwok {
			osp.sendLoginForm(w, r, req, "Wrong username or password!")
			return nil
		}

		// password is confirmed okay
		obSess := NewSessionFromLDAP(ldapuser)
		if err := obSess.SaveSession(osp.oa); err != nil {
			osp.sendLoginForm(w, r, req, "Failed to save session!")
			log.WithError(err).Error("Failed to write session to redis!")
			return nil
		}

		http.SetCookie(w, obSess.Cookie(osp.oa))
		return obSess.SAMLSession(osp.oa)
	}

	if sessionCookie, err := r.Cookie("outback_session"); err == nil {
		obSess, err := LoadSessionByID(sessionCookie.Value, osp.oa)
		if err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			log.WithError(err).Error("Failed to load session by ID!")
			return nil
		}

		if obSess == nil {
			// no error but no cookie
			osp.sendLoginForm(w, r, req, "")
			log.WithField("id", sessionCookie.Value).Debug("found cookie but missing redis session")
			return nil
		}

		// the session is good!
		return obSess.SAMLSession(osp.oa)
	}

	log.Debug("no session, sending raw login form")
	osp.sendLoginForm(w, r, req, "")

	return nil
}

func (osp *OutbackSessionProvider) sendLoginForm(w http.ResponseWriter, r *http.Request, req *saml.IdpAuthnRequest, msg string) {

	samlRequest := ""
	relayState := ""
	if req != nil {
		samlRequest = base64.StdEncoding.EncodeToString(req.RequestBuffer)
		relayState = req.RelayState
	}

	destURL := r.URL
	destURL.RawQuery = ""
	//destURL = osp.oa.Config.BaseURL.ResolveReference(destURL)

	if err := osp.oa.templates.Lookup("login.html").Execute(w, struct {
		Message     string
		URL         string
		SAMLRequest string
		RelayState  string
	}{
		Message:     msg,
		URL:         destURL.String(),
		SAMLRequest: samlRequest,
		RelayState:  relayState,
	}); err != nil {
		panic(err)
	}

}

func newSessionID() string {
	rv := make([]byte, 24)
	if _, err := saml.RandReader.Read(rv); err != nil {
		panic(err)
	}
	return base64.StdEncoding.EncodeToString(rv)
}
