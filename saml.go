package outback

import (
	"errors"
	"io/ioutil"

	"encoding/xml"

	"github.com/parryjacob/saml"
)

func loadSAMLSPMetadata(fn string) (*saml.EntityDescriptor, error) {
	bytes, err := ioutil.ReadFile(fn)
	if err != nil {
		return nil, nil
	}

	spMetadata := &saml.EntityDescriptor{}
	if err := xml.Unmarshal(bytes, spMetadata); err != nil {
		entities := &saml.EntitiesDescriptor{}

		if err := xml.Unmarshal(bytes, entities); err != nil {
			return nil, err
		}

		// loaded entities
		for _, e := range entities.EntityDescriptors {
			if len(e.SPSSODescriptors) > 0 {
				return &e, nil
			}
		}

		return nil, errors.New("no service provider found in metadata")
	}

	return spMetadata, nil
}

func metadataHasACSEndpoint(meta *saml.EntityDescriptor) bool {
	for _, spsso := range meta.SPSSODescriptors {
		for _, endpoint := range spsso.AssertionConsumerServices {
			if endpoint.Binding == saml.HTTPPostBinding {
				return true
			}
		}
	}
	return false
}
