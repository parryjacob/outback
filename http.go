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

	r.HandleFunc("/metadata", oa.idp.ServeMetadata)
	r.HandleFunc("/sso", oa.idp.ServeSSO)
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
