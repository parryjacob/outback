package outback

import (
	"crypto/md5"
	"html/template"
	"net/http"
	"strconv"

	"time"

	"encoding/hex"

	log "github.com/Sirupsen/logrus"
	"github.com/gorilla/mux"
	"github.com/parryjacob/saml"
)

func (oa *OutbackApp) httpIDPList(w http.ResponseWriter, r *http.Request) {
	sess := oa.sessionProvider.GetSession(w, r, nil)
	if sess == nil {
		return
	}

	idpHashes := make(map[string]string, 0)
	for entityID, sp := range oa.serviceProviderProvider.providers {
		h := md5.New()
		h.Write([]byte(entityID))

		if metadataHasACSEndpoint(sp) {
			idpHashes[entityID] = hex.EncodeToString(h.Sum(nil))
		}
	}

	if err := oa.templates.Lookup("sp_list.html").Execute(w, struct {
		SPs map[string]string
	}{
		SPs: idpHashes,
	}); err != nil {
		panic(err)
	}
}

func (oa *OutbackApp) httpIDPInitiated(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	hash := vars["hash"]
	var metadata *saml.EntityDescriptor
	for entityID, sp := range oa.serviceProviderProvider.providers {
		h := md5.New()
		h.Write([]byte(entityID))
		sphash := hex.EncodeToString(h.Sum(nil))

		if sphash == hash {
			metadata = sp
			break
		}
	}
	if metadata == nil {
		http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
		return
	}

	// Do the IDP initiated flow
	oa.idp.ServeIDPInitiated(w, r, metadata.EntityID, "")
}

func (oa *OutbackApp) httpIndex(w http.ResponseWriter, r *http.Request) {
	session := oa.GetOutbackSession(w, r, nil)
	if session == nil {
		return
	}
	if err := oa.templates.Lookup("home.html").Execute(w, struct {
		User *LDAPUser
	}{
		User: session.ldapUser,
	}); err != nil {
		panic(err)
	}
}

func (oa *OutbackApp) httpLogout(w http.ResponseWriter, r *http.Request) {
	session := oa.GetOutbackSession(w, r, nil)
	if session == nil {
		return
	}

	if err := session.Destroy(oa, w, r); err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		log.WithError(err).Error("Failed to destroy user session")
		return
	}

	if err := oa.templates.Lookup("logged_out.html").Execute(w, nil); err != nil {
		panic(err)
	}
}

func (oa *OutbackApp) parseTemplates() error {
	oa.templates = template.New("")
	_, err := oa.templates.ParseGlob("templates/*.html")
	return err
}

func (oa *OutbackApp) serveHTTP() error {
	if err := oa.parseTemplates(); err != nil {
		return err
	}

	r := mux.NewRouter()

	r.HandleFunc("/", oa.httpIndex)
	r.HandleFunc("/logout", oa.httpLogout)

	// Basic SSO
	r.HandleFunc("/metadata", oa.idp.ServeMetadata)
	r.HandleFunc("/sso", oa.idp.ServeSSO)

	// IdP Initiated flow
	r.HandleFunc("/sps", oa.httpIDPList)
	r.HandleFunc("/idpinit/{hash}", oa.httpIDPInitiated)

	// LDAP Self Serve
	if oa.Config.SelfServe {
		r.HandleFunc("/changepw", oa.httpSSChangePassword)
	}

	addr := oa.Config.ListenAddress + ":" + strconv.Itoa(oa.Config.Port)

	srv := &http.Server{
		Handler:      r,
		Addr:         addr,
		WriteTimeout: 30 * time.Second,
		ReadTimeout:  30 * time.Second,
	}

	log.Info("Starting HTTP server on " + addr + "...")

	return srv.ListenAndServe()
}
