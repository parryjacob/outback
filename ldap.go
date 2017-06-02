package outback

import (
	"crypto/tls"
	"fmt"
	"strings"

	log "github.com/Sirupsen/logrus"
	"gopkg.in/ldap.v2"
)

// LDAPUser defines a user from LDAP
type LDAPUser struct {
	DN        string
	CN        string
	SN        string
	GivenName string
	Username  string
	Email     string
}

func (oa *OutbackApp) getLDAP(bind bool) (conn *ldap.Conn, err error) {
	if bind && oa.ldap != nil {
		return oa.ldap, nil
	}

	addr := fmt.Sprintf("%s:%d", oa.Config.LDAPConfig.Host, oa.Config.LDAPConfig.Port)

	if !oa.Config.LDAPConfig.Secure {
		conn, err = ldap.Dial("tcp", addr)
	} else {
		conn, err = ldap.DialTLS("tcp", addr, &tls.Config{
			InsecureSkipVerify: true,
		})
	}

	if err != nil {
		log.WithError(err).Debug("LDAP connection failed in getLDAP")
		return nil, err
	}

	if bind {
		log.Debugf("Binding to LDAP as %s", oa.Config.LDAPConfig.BindDN)
		err = conn.Bind(oa.Config.LDAPConfig.BindDN, oa.Config.LDAPConfig.BindPW)
		if err != nil {
			defer conn.Close()
			return nil, err
		}
		oa.ldap = conn
	}

	return conn, err
}

func (oa *OutbackApp) ldapSRToUser(conn *ldap.Conn, sr *ldap.SearchRequest) (*LDAPUser, error) {
	s, err := conn.Search(sr)
	if err != nil {
		return nil, err
	}

	for _, e := range s.Entries {
		user := LDAPUser{
			DN:        e.DN,
			CN:        e.GetAttributeValue("cn"),
			SN:        e.GetAttributeValue("sn"),
			GivenName: e.GetAttributeValue("givenName"),
			Username:  e.GetAttributeValue(oa.Config.LDAPConfig.UsernameAttribute),
			Email:     e.GetAttributeValue("mail"),
		}
		log.Debugf("Found entry: %s", e.DN)
		return &user, nil
	}
	return nil, nil
}

func (oa *OutbackApp) ldapAttributes() []string {
	return []string{
		"cn", "sn", "givenName", "mail",
		oa.Config.LDAPConfig.UsernameAttribute,
	}
}

func (oa *OutbackApp) ldapFilter(addFilter string) string {
	filter := oa.Config.LDAPConfig.UserFilter

	if len(filter) > 0 {
		if !strings.HasPrefix(filter, "(") {
			filter = "(" + filter
		}
		if !strings.HasSuffix(filter, ")") {
			filter += ")"
		}
	}

	if len(addFilter) > 0 {
		if !strings.HasPrefix(addFilter, "(") {
			addFilter = "(" + addFilter
		}
		if !strings.HasSuffix(addFilter, ")") {
			addFilter += ")"
		}

		if len(filter) > 0 {
			filter = "(&" + filter + addFilter + ")"
		} else {
			filter = addFilter
		}
	}
	return filter
}

// FindLDAPUser will search for an LDAP user with the particular name
func (oa *OutbackApp) FindLDAPUser(name string) (*LDAPUser, error) {
	conn, err := oa.getLDAP(true)
	if err != nil {
		return nil, err
	}

	for _, dn := range oa.Config.LDAPConfig.BaseDN {
		filter := "(" + oa.Config.LDAPConfig.UsernameAttribute + "=" + name + ")"

		sr := ldap.NewSearchRequest(
			dn, // Base DN
			ldap.ScopeWholeSubtree, // search scope
			ldap.NeverDerefAliases, // deref aliases
			0, 0, // timeouts
			false, // types only
			oa.ldapFilter(filter), // filter
			oa.ldapAttributes(),   // attributes
			nil,                   // controls
		)

		user, err := oa.ldapSRToUser(conn, sr)

		if err != nil {
			return nil, err
		}
		if user != nil {
			return user, nil
		}

	}
	return nil, nil
}

// FindLDAPUserByDN will attempt to find a user directly by their DN
func (oa *OutbackApp) FindLDAPUserByDN(dn string) (*LDAPUser, error) {
	conn, err := oa.getLDAP(true)
	if err != nil {
		return nil, err
	}
	sr := ldap.NewSearchRequest(
		dn,
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0, 0,
		false,
		oa.ldapFilter(""),
		oa.ldapAttributes(),
		nil,
	)
	return oa.ldapSRToUser(conn, sr)
}

// TestLDAPUserPassword will attempt to bind as a user
func (oa *OutbackApp) TestLDAPUserPassword(user *LDAPUser, password string) (bool, error) {
	conn, err := oa.getLDAP(false)
	if err != nil {
		return false, err
	}
	defer conn.Close()

	err = conn.Bind(user.DN, password)
	if err != nil {
		// code 49 is "Invalid Credentials"
		if strings.Contains(err.Error(), "LDAP Result Code 49") {
			return false, nil
		}
		return false, err
	}

	return true, nil
}
