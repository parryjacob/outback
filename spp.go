package outback

import (
	"crypto/md5"
	"net/http"

	"io/ioutil"
	"path"
	"strings"

	"os"

	"encoding/hex"

	log "github.com/Sirupsen/logrus"
	"github.com/parryjacob/saml"
)

type OutbackSAMLProviderConfig struct {
	EntityID     string
	IDPInitiated bool
	DisplayName  string
}

// GetHash will return the MD5 hash of the entityID
func (ospc *OutbackSAMLProviderConfig) GetHash() string {
	h := md5.New()
	h.Write([]byte(ospc.EntityID))
	return hex.EncodeToString(h.Sum(nil))
}

// GetName will get the best option for a display name for this provider
func (ospc *OutbackSAMLProviderConfig) GetName() string {
	if len(ospc.DisplayName) > 0 {
		return ospc.DisplayName
	}
	return ospc.EntityID
}

type OutbackServiceProviderProvider struct {
	oa        *OutbackApp
	providers map[string]*saml.EntityDescriptor
}

// GetServiceProvider will return the service provider requested by name
func (ospp *OutbackServiceProviderProvider) GetServiceProvider(r *http.Request, serviceProviderID string) (prov *saml.EntityDescriptor, err error) {
	var ok bool
	if prov, ok = ospp.providers[serviceProviderID]; !ok {
		return nil, os.ErrNotExist
	}
	return prov, nil
}

func (ospp *OutbackServiceProviderProvider) loadServiceProviders(directory string) error {
	ospp.providers = make(map[string]*saml.EntityDescriptor)
	log.Debug("Loading stored metadata...")

	files, err := ioutil.ReadDir(directory)
	if err != nil {
		return err
	}

	for _, f := range files {
		if f.IsDir() {
			continue
		}
		if strings.HasSuffix(strings.ToLower(f.Name()), ".xml") {
			meta, err := loadSAMLSPMetadata(path.Join(directory, f.Name()))
			if err != nil {
				return err
			}
			ospp.providers[meta.EntityID] = meta
			log.WithField("entityID", meta.EntityID).Debug("Loaded service provider")
		}
	}

	log.WithField("num", len(ospp.providers)).Debug("Loaded stored metadata.")

	return nil
}
