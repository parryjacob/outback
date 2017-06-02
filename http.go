package outback

import (
	"crypto/md5"
	"encoding/xml"
	"html/template"
	"net/http"
	"strconv"

	"time"

	"encoding/hex"

	log "github.com/Sirupsen/logrus"
	"github.com/gorilla/mux"
	"github.com/parryjacob/saml"
)

func (oa *OutbackApp) httpMetadata(w http.ResponseWriter, r *http.Request) {
	buf, _ := xml.MarshalIndent(oa.idp.Metadata(), "", "  ")
	w.Header().Set("Content-Type", "application/samlmetadata+xml")
	w.WriteHeader(http.StatusOK)
	w.Write(buf)
}

// This is functionally identical to ServeSSO in identity_provider.go in the
// saml package.
func (oa *OutbackApp) httpSSO(w http.ResponseWriter, r *http.Request) {
	oa.idp.ServeSSO(w, r)

	/*authnreq, err := saml.NewIdpAuthnRequest(oa.idp, r)
	if err != nil {
		log.WithError(err).Debug("Received malformatted authn request")
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}

	if err := authnreq.Validate(); err != nil {
		log.WithError(err).Warn("Failed to validate authn request")
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}

	session := oa.idp.SessionProvider.GetSession(w, r, authnreq)
	if session == nil {
		// This usually means that we're going to prompt the user for
		// their login and shouldn't continue the SAML request
		return
	}

	// make and return the assertion
	if err := oa.idp.AssertionMaker.MakeAssertion(authnreq, session); err != nil {
		log.WithError(err).Error("Failed to make assertion")
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	if err := authnreq.WriteResponse(w); err != nil {
		log.WithError(err).Error("Failed to write authn response")
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}*/
}

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

	r.HandleFunc("/metadata", oa.httpMetadata)
	r.HandleFunc("/sso", oa.httpSSO)
	r.HandleFunc("/sps", oa.httpIDPList)
	r.HandleFunc("/idpinit/{hash}", oa.httpIDPInitiated)

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
