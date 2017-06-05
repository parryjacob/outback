package outback

import (
	"crypto"
	"crypto/x509"
	"errors"
	"net/url"
	"time"

	"strings"

	"github.com/BurntSushi/toml"
	log "github.com/Sirupsen/logrus"
)

// Config represents the config of an Outback instance
type Config struct {
	tomlMetadata *toml.MetaData
	pluginConfig map[string]toml.Primitive

	BaseURL           *url.URL
	PrivateKey        crypto.PrivateKey
	Certificate       *x509.Certificate
	Port              int
	MetadataDirectory string
	PluginDirectory   string
	Debug             bool
	ListenAddress     string
	LDAPConfig        *ldapConfig
	RedisURI          string
	CookieLifetime    time.Duration
	SelfServe         bool

	SAMLProviderConfigs []OutbackSAMLProviderConfig
}

type ldapConfig struct {
	Host              string
	Port              int
	Secure            bool
	BindDN            string
	BindPW            string
	BaseDN            []string
	GroupDN           []string
	UsernameAttribute string
	GroupAttribute    string
	UserFilter        string
	RootCA            *x509.Certificate
	ActiveDirectory   bool

	PasswordPolicy *passwordPolicyConfig
}

type passwordPolicyConfig struct {
	MinLength  int
	Symbols    bool
	Numbers    bool
	Capitals   bool
	UserChange bool // if true, we bind and change the pwd as the user
}

type configFile struct {
	BaseURL               string
	KeyFile               string
	CertFile              string
	Port                  int
	MetadataDirectory     string
	PluginDirectory       string
	Debug                 bool
	ListenAddress         string
	LDAPHost              string
	LDAPS                 bool
	LDAPPort              int
	LDAPBindDN            string
	LDAPBindPW            string
	LDAPBaseDN            []string
	LDAPGroupDN           []string
	LDAPUsernameAttribute string
	LDAPUserFilter        string
	LDAPGroupAttribute    string
	LDAPRootCA            string
	LDAPActiveDirectory   bool
	RedisURI              string
	CookieLifetime        string
	SelfServe             bool

	PasswordMinLength    int
	PasswordMustNumbers  bool
	PasswordMustCapital  bool
	PasswordMustSymbol   bool
	PasswordChangeAsUser bool

	Plugins             map[string]toml.Primitive
	SAMLProviderConfigs []OutbackSAMLProviderConfig `toml:"metadata"`
}

func (oa *OutbackApp) loadConfig(configPath string) (err error) {
	c := configFile{
		BaseURL:               "http://localhost",
		KeyFile:               "idp-key.pem",
		CertFile:              "idp-cert.pem",
		Port:                  80,
		MetadataDirectory:     "metadata",
		PluginDirectory:       "plugins",
		Debug:                 false,
		ListenAddress:         "127.0.0.1",
		LDAPHost:              "127.0.0.1",
		LDAPPort:              0,
		LDAPS:                 false,
		LDAPBaseDN:            []string{},
		LDAPGroupDN:           []string{},
		LDAPUsernameAttribute: "sAMAccountName",
		RedisURI:              "localhost:6379",
		CookieLifetime:        "168h",
		LDAPUserFilter:        "(objectClass=user)",
		LDAPGroupAttribute:    "memberOf",
		LDAPRootCA:            "",
		LDAPActiveDirectory:   false,
		SelfServe:             false,

		PasswordMinLength:    8,
		PasswordMustCapital:  false,
		PasswordMustNumbers:  false,
		PasswordMustSymbol:   false,
		PasswordChangeAsUser: false,

		Plugins:             map[string]toml.Primitive{},
		SAMLProviderConfigs: []OutbackSAMLProviderConfig{},
	}

	tomlMeta, err := toml.DecodeFile(configPath, &c)
	if err != nil {
		return err
	}

	config := Config{}

	// parse the base URL
	if config.BaseURL, err = url.Parse(c.BaseURL); err != nil {
		return err
	}

	// load the keys+certs
	if config.PrivateKey, config.Certificate, err = parseKeyAndCertificate(c.KeyFile, c.CertFile); err != nil {
		return err
	}

	// set default LDAP ports
	if c.LDAPPort == 0 {
		if c.LDAPS {
			c.LDAPPort = 636
		} else {
			c.LDAPPort = 389
		}
	}

	// setup the LDAP config
	lc := ldapConfig{
		Host:              c.LDAPHost,
		Port:              c.LDAPPort,
		Secure:            c.LDAPS,
		BindDN:            c.LDAPBindDN,
		BindPW:            c.LDAPBindPW,
		BaseDN:            c.LDAPBaseDN,
		GroupDN:           c.LDAPGroupDN,
		UsernameAttribute: c.LDAPUsernameAttribute,
		UserFilter:        c.LDAPUserFilter,
		GroupAttribute:    c.LDAPGroupAttribute,
		ActiveDirectory:   c.LDAPActiveDirectory,
		PasswordPolicy: &passwordPolicyConfig{
			MinLength:  c.PasswordMinLength,
			Capitals:   c.PasswordMustCapital,
			Symbols:    c.PasswordMustSymbol,
			Numbers:    c.PasswordMustNumbers,
			UserChange: c.PasswordChangeAsUser,
		},
	}

	// load the LDAP root CA
	if c.LDAPS && len(c.LDAPRootCA) == 0 {
		return errors.New("using LDAP over SSL needs a root CA specified")
	}
	if len(c.LDAPRootCA) > 0 {
		ldapRootCert, err := parsePEMCert(c.LDAPRootCA)
		if err != nil {
			return err
		}
		lc.RootCA = ldapRootCert
	}

	// set the LDAP config
	config.LDAPConfig = &lc

	// cookies
	if config.CookieLifetime, err = time.ParseDuration(c.CookieLifetime); err != nil {
		return err
	}

	// misc settings that don't require parsing
	config.Port = c.Port
	config.MetadataDirectory = c.MetadataDirectory
	config.Debug = c.Debug
	config.ListenAddress = c.ListenAddress
	config.RedisURI = c.RedisURI
	config.SelfServe = c.SelfServe
	config.PluginDirectory = c.PluginDirectory
	config.tomlMetadata = &tomlMeta
	config.pluginConfig = c.Plugins
	config.SAMLProviderConfigs = c.SAMLProviderConfigs

	oa.Config = &config

	return nil
}

// DecodePluginConfig will attempt to decode the plugin configuration
func (oc *Config) DecodePluginConfig(plugin string, i interface{}) error {
	if strings.HasSuffix(plugin, ".so") {
		plugin = plugin[:len(plugin)-3]
	}

	prim, ok := oc.pluginConfig[plugin]
	if !ok {
		log.Debugf("Requested config for plugin '%s', but no Primitive found", plugin)
		return nil
	}

	return oc.tomlMetadata.PrimitiveDecode(prim, i)
}

// GetSAMLProviderConfig will return any custom configuration for the SAML
// provider or a default set of options
func (oc *Config) GetSAMLProviderConfig(entityID string) *OutbackSAMLProviderConfig {
	for _, conf := range oc.SAMLProviderConfigs {
		if conf.EntityID == entityID {
			return &conf
		}
	}
	return &OutbackSAMLProviderConfig{
		EntityID:     entityID,
		IDPInitiated: true,
		DisplayName:  entityID,
	}
}
