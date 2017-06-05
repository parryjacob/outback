package main

import (
	"errors"
	"strings"

	log "github.com/Sirupsen/logrus"
	"github.com/parryjacob/outback"
	"github.com/parryjacob/saml"
)

type GSuiteConfig struct {
	Domain string
}

var gConfig *GSuiteConfig

func Initialize(oa *outback.OutbackApp, pluginName string) error {
	log.Debug("Initializing G Suite plugin...")
	gConfig = &GSuiteConfig{}
	if err := oa.Config.DecodePluginConfig(pluginName, gConfig); err != nil {
		log.WithError(err).Error("Failed to decode G Suite config!")
		return err
	}

	if len(gConfig.Domain) == 0 {
		return errors.New("G Suite domain must be provided")
	}

	return nil
}

func AlterAssertion(user *outback.LDAPUser, sp *saml.EntityDescriptor, assertion *saml.Assertion) error {
	if !strings.HasPrefix(sp.EntityID, "google.com") {
		return nil
	}

	assertion.Subject.NameID.Value = user.Username + "@" + gConfig.Domain
	assertion.Subject.NameID.Format = "urn:oasis:names:tc:SAML:2.0:nameid-format:email"
	assertion.Subject.NameID.SPNameQualifier = "google.com/a/" + gConfig.Domain

	return nil
}
