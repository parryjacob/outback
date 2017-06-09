package outback

import (
	"net"
	"net/http"
	"strconv"

	"time"

	"strings"

	log "github.com/Sirupsen/logrus"
	"github.com/gorilla/mux"
	"github.com/parryjacob/saml"
	"github.com/unrolled/render"
)

func (oa *OutbackApp) remoteAddr(r *http.Request) net.IP {
	ra := r.RemoteAddr

	if ss := strings.Split(ra, ":"); len(ss) > 1 {
		ra = strings.Join(ss[:len(ss)-1], ":")
	}

	if oa.Config.TrustXFF {
		xff := r.Header.Get("X-Forwarded-For")
		if len(xff) > 0 {
			ra = xff
			if strings.Contains(ra, ",") {
				ra = strings.Split(ra, ",")[0]
			}
		}
	}

	ra = strings.TrimSpace(ra)
	ra = strings.Trim(ra, "[]")

	return net.ParseIP(ra)
}

func (oa *OutbackApp) httpIDPList(w http.ResponseWriter, r *http.Request) {
	sess := oa.sessionProvider.GetSession(w, r, nil)
	if sess == nil {
		return
	}

	sps := map[string]*OutbackSAMLProviderConfig{}
	for entityID, sp := range oa.serviceProviderProvider.providers {
		samlConfig := oa.Config.GetSAMLProviderConfig(entityID)

		if metadataHasACSEndpoint(sp) && samlConfig.IDPInitiated {
			sps[entityID] = samlConfig
		}
	}

	if err := oa.RenderTemplate("sp_list", w, struct {
		SPs map[string]*OutbackSAMLProviderConfig
	}{
		SPs: sps,
	}); err != nil {
		panic(err)
	}
}

func (oa *OutbackApp) httpIDPInitiated(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	hash := vars["hash"]
	var metadata *saml.EntityDescriptor
	for entityID, sp := range oa.serviceProviderProvider.providers {
		samlConfig := oa.Config.GetSAMLProviderConfig(entityID)

		if hash == samlConfig.GetHash() && samlConfig.IDPInitiated {
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
	if err := oa.RenderTemplate("home", w, struct {
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

	if err := oa.RenderTemplate("logged_out", w, nil); err != nil {
		panic(err)
	}
}

func (oa *OutbackApp) httpFakeSLO(w http.ResponseWriter, r *http.Request) {
	if err := oa.RenderTemplate("sp_logout", w, nil); err != nil {
		panic(err)
	}
}

func (oa *OutbackApp) serveHTTP() error {
	oa.render = render.New(render.Options{
		IsDevelopment: oa.Config.Debug,
		Layout:        "layouts/base",
	})

	r := mux.NewRouter()

	r.HandleFunc("/", oa.httpIndex)
	r.HandleFunc("/logout", oa.httpLogout)

	// Basic SSO
	r.HandleFunc("/metadata", oa.idp.ServeMetadata)
	r.HandleFunc("/sso", oa.idp.ServeSSO)
	r.HandleFunc("/slo", oa.httpFakeSLO)

	// IdP Initiated flow
	r.HandleFunc("/sps", oa.httpIDPList)
	r.HandleFunc("/idpinit/{hash}", oa.httpIDPInitiated)

	// LDAP Self Serve
	if oa.Config.SelfServe {
		r.HandleFunc("/changepw", oa.httpSSChangePassword)
	}

	// Static content
	r.PathPrefix("/static").Handler(http.StripPrefix("/static/", http.FileServer(http.Dir("./static/"))))

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
