package outback

import (
	"crypto"
	"crypto/x509"
	"errors"
	"net/url"
	"time"

	"github.com/BurntSushi/toml"
)

// Config represents the config of an Outback instance
type Config struct {
	BaseURL           *url.URL
	PrivateKey        crypto.PrivateKey
	Certificate       *x509.Certificate
	Port              int
	MetadataDirectory string
	Debug             bool
	ListenAddress     string
	LDAPConfig        *ldapConfig
	RedisURI          string
	CookieLifetime    time.Duration
}

type ldapConfig struct {
	Host              string
	Port              int
	Secure            bool
	BindDN            string
	BindPW            string
	BaseDN            []string
	UsernameAttribute string
	GroupAttribute    string
	UserFilter        string
	RootCA            *x509.Certificate
}

type configFile struct {
	BaseURL               string
	KeyFile               string
	CertFile              string
	Port                  int
	MetadataDirectory     string
	Debug                 bool
	ListenAddress         string
	LDAPHost              string
	LDAPS                 bool
	LDAPPort              int
	LDAPBindDN            string
	LDAPBindPW            string
	LDAPBaseDN            []string
	LDAPUsernameAttribute string
	LDAPUserFilter        string
	LDAPGroupAttribute    string
	LDAPRootCA            string
	RedisURI              string
	CookieLifetime        string
}

func (oa *OutbackApp) loadConfig(configPath string) (err error) {
	c := configFile{
		BaseURL:               "http://localhost",
		KeyFile:               "idp-key.pem",
		CertFile:              "idp-cert.pem",
		Port:                  80,
		MetadataDirectory:     "metadata",
		Debug:                 false,
		ListenAddress:         "127.0.0.1",
		LDAPHost:              "127.0.0.1",
		LDAPPort:              0,
		LDAPS:                 false,
		LDAPBaseDN:            make([]string, 0),
		LDAPUsernameAttribute: "sAMAccountName",
		RedisURI:              "localhost:6379",
		CookieLifetime:        "168h",
		LDAPUserFilter:        "(objectClass=user)",
		LDAPGroupAttribute:    "memberOf",
		LDAPRootCA:            "",
	}
	if _, err := toml.DecodeFile(configPath, &c); err != nil {
		return nil
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
		UsernameAttribute: c.LDAPUsernameAttribute,
		UserFilter:        c.LDAPUserFilter,
		GroupAttribute:    c.LDAPGroupAttribute,
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

	oa.Config = &config

	return nil
}
