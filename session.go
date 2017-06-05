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
	log.WithField("dn", user.DN).Debug("Creating new session for user")
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

// Destroy will attempt to delete the session in Redis and update the user's cookie
func (os *OutbackSession) Destroy(oa *OutbackApp, w http.ResponseWriter, r *http.Request) error {
	rd, err := oa.getRedis()
	if err != nil {
		return err
	}
	if err := rd.Del("outback::session::" + os.ID).Err(); err != nil {
		return err
	}
	http.SetCookie(w, &http.Cookie{
		Name:     "outback_session",
		Value:    "",
		MaxAge:   -1,
		HttpOnly: false,
		Path:     "/",
	})
	return nil
}

// LoadSessionByID will attempt to load a session from JSON
func LoadSessionByID(id string, oa *OutbackApp) (*OutbackSession, error) {
	if len(id) == 0 {
		return nil, nil
	}

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

// GetOutbackSession will get the outback session for the current user or prompt for a login form
func (oa *OutbackApp) GetOutbackSession(w http.ResponseWriter, r *http.Request, vars map[string]string) *OutbackSession {
	r.ParseForm()

	// Check if we're attempting to login
	if r.Method == "POST" && r.PostForm.Get("user") != "" {
		username := r.PostForm.Get("user")
		password := r.PostForm.Get("password")

		ldapuser, err := oa.FindLDAPUser(username)
		if err != nil {
			oa.sendLoginForm(w, r, vars, "Error attempting to check login!")
			log.WithError(err).WithField("username", username).Error("Failed to check for LDAP user")
			return nil
		}

		// no user
		if ldapuser == nil {
			oa.sendLoginForm(w, r, vars, "Wrong username or password!")
			return nil
		}

		// user is good, check the password
		pwok, err := oa.TestLDAPUserPassword(ldapuser, password)
		if err != nil {
			oa.sendLoginForm(w, r, vars, "Error attempting to check password!")
			log.WithError(err).WithField("username", username).Error("Failed to check LDAP password")
			return nil
		}

		// wrong password
		if !pwok {
			oa.sendLoginForm(w, r, vars, "Wrong username or password!")
			return nil
		}

		// password is confirmed okay
		obSess := NewSessionFromLDAP(ldapuser)
		if err := obSess.SaveSession(oa); err != nil {
			oa.sendLoginForm(w, r, vars, "Failed to save session!")
			log.WithError(err).Error("Failed to write session to redis!")
			return nil
		}

		http.SetCookie(w, obSess.Cookie(oa))
		return obSess
	}

	if sessionCookie, err := r.Cookie("outback_session"); err == nil {
		obSess, err := LoadSessionByID(sessionCookie.Value, oa)
		if err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			log.WithError(err).Error("Failed to load session by ID!")
			return nil
		}

		if obSess == nil {
			// no error but no cookie
			oa.sendLoginForm(w, r, vars, "")
			log.WithField("id", sessionCookie.Value).Debug("Found cookie but missing redis session")
			return nil
		}

		// the session is good!
		return obSess
	}

	oa.sendLoginForm(w, r, vars, "")

	return nil
}

// GetSession returns a saml.Session or nil for the passed request
func (osp *OutbackSessionProvider) GetSession(w http.ResponseWriter, r *http.Request, req *saml.IdpAuthnRequest) *saml.Session {
	vars := make(map[string]string, 0)
	if req != nil {
		vars["SAMLRequest"] = base64.StdEncoding.EncodeToString(req.RequestBuffer)
		vars["RelayState"] = req.RelayState
	}

	session := osp.oa.GetOutbackSession(w, r, vars)
	if session == nil {
		return nil
	}

	return session.SAMLSession(osp.oa)
}

func (oa *OutbackApp) sendLoginForm(w http.ResponseWriter, r *http.Request, vars map[string]string, msg string) {
	destURL := r.URL
	destURL.RawQuery = ""
	//destURL = osp.oa.Config.BaseURL.ResolveReference(destURL)

	if err := oa.templates.Lookup("login.html").Execute(w, struct {
		Message     string
		URL         string
		SAMLRequest string
		Vars        map[string]string
	}{
		Message: msg,
		URL:     destURL.String(),
		Vars:    vars,
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
