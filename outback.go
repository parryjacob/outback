package outback

import (
	"html/template"
	"net/url"

	log "github.com/Sirupsen/logrus"
	"github.com/go-redis/redis"
	"github.com/parryjacob/saml"
	"gopkg.in/ldap.v2"
)

// OutbackApp represents the state of an Outback instance
type OutbackApp struct {
	Config                  *Config
	serviceProviderProvider *OutbackServiceProviderProvider
	sessionProvider         *OutbackSessionProvider
	idp                     *saml.IdentityProvider
	ldap                    *ldap.Conn
	redis                   *redis.Client
	templates               *template.Template
}

// New creates and returns a new OutbackApp given a configuration path
func New(configPath string) (*OutbackApp, error) {
	oa := &OutbackApp{
		ldap: nil,
	}
	if err := oa.loadConfig(configPath); err != nil {
		return nil, err
	}

	if oa.Config.Debug {
		log.SetLevel(log.DebugLevel)
	}

	oa.serviceProviderProvider = &OutbackServiceProviderProvider{}
	if err := oa.serviceProviderProvider.loadServiceProviders(oa.Config.MetadataDirectory); err != nil {
		return nil, err
	}

	oa.sessionProvider = &OutbackSessionProvider{
		oa: oa,
	}

	mdurl, _ := url.Parse("metadata")
	ssourl, _ := url.Parse("sso")

	oa.idp = &saml.IdentityProvider{
		Key:                     oa.Config.PrivateKey,
		Certificate:             oa.Config.Certificate,
		ServiceProviderProvider: oa.serviceProviderProvider,
		AssertionMaker:          OutbackAssertionMaker{},
		MetadataURL:             *oa.Config.BaseURL.ResolveReference(mdurl),
		SSOURL:                  *oa.Config.BaseURL.ResolveReference(ssourl),
		Logger:                  log.New(),
		SessionProvider:         oa.sessionProvider,
	}

	return oa, nil
}

// Run starts Outback
func (oa *OutbackApp) Run() error {
	_, err := oa.getLDAP(true)
	if err != nil {
		log.WithError(err).Error("Could not connect to LDAP!")
		return err
	}
	log.Debugf("LDAP connected to %s:%d", oa.Config.LDAPConfig.Host, oa.Config.LDAPConfig.Port)

	if oa.Config.LDAPConfig.ActiveDirectory {
		log.Info("Outback is operating in Active Directory compatibility mode")
		log.Info("You must use an administrative user to bind to LDAP if you wish to use self-serve features")
	}

	return oa.serveHTTP()
}
