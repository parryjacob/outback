package outback

import (
	"net/http"

	"io/ioutil"
	"path"
	"strings"

	"os"

	log "github.com/Sirupsen/logrus"
	"github.com/parryjacob/saml"
)

type OutbackServiceProviderProvider struct {
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
