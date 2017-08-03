package outback

import (
	"crypto/tls"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/text/encoding/unicode"

	"crypto/x509"

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
	Groups    []string
}

// HasGroup returns whether this user has the specified group (case insensitive)
func (u *LDAPUser) HasGroup(g string) bool {
	for _, group := range u.Groups {
		if strings.EqualFold(group, g) {
			return true
		}
	}
	return false
}

func (oa *OutbackApp) getLDAP(bind bool) (conn *ldap.Conn, err error) {
	if bind && oa.ldap != nil {
		// TODO: we should test this connection

		return oa.ldap, nil
	}

	addr := fmt.Sprintf("%s:%d", oa.Config.LDAPConfig.Host, oa.Config.LDAPConfig.Port)

	if !oa.Config.LDAPConfig.Secure {
		conn, err = ldap.Dial("tcp", addr)
	} else {
		rootPool := x509.NewCertPool()
		rootPool.AddCert(oa.Config.LDAPConfig.RootCA)

		tlsc := &tls.Config{
			InsecureSkipVerify: oa.Config.LDAPConfig.AllowInsecure,
			RootCAs:            rootPool,
			ServerName:         oa.Config.LDAPConfig.Host,
		}

		// We limit our maximum TLS version to TLS 1.1 here
		// because there seems to be an issue with Active Directory
		// and using TLS 1.2 with 512-bit ciphers.
		// Go currently only has 256-bit TLS 1.2 ciphers, and if you
		// attempt to connect to AD it will just reset the connection
		// instead of negotiating with a 256-bit cipher.
		if oa.Config.LDAPConfig.ActiveDirectory {
			tlsc.MaxVersion = tls.VersionTLS11
		}

		conn, err = ldap.DialTLS("tcp", addr, tlsc)
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

func (oa *OutbackApp) ldapSRToUser(sr *ldap.SearchRequest) (*LDAPUser, error) {
	conn, err := oa.getLDAP(true)
	if err != nil {
		return nil, err
	}

	s, err := conn.Search(sr)
	if err != nil {

		// If we were disconnected, try again
		if ldap.IsErrorWithCode(err, ldap.ErrorNetwork) {
			oa.ldap = nil
			return oa.ldapSRToUser(sr)
		}

		oa.ldap = nil
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
			Groups:    []string{},
		}

		for _, group := range e.GetAttributeValues(oa.Config.LDAPConfig.GroupAttribute) {
			for _, base := range oa.Config.LDAPConfig.GroupDN {
				if strings.HasSuffix(strings.ToLower(group), strings.ToLower(base)) {
					group = group[:len(group)-len(base)-1]
					bits := strings.SplitN(group, "=", 2)
					if len(bits) == 2 {
						group = bits[1]

						// only get the first one
						if strings.Contains(group, ",") {
							bits = strings.Split(group, ",")
							group = bits[0]
						}

						user.Groups = append(user.Groups, bits[1])
					}

					break
				}
			}
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
		oa.Config.LDAPConfig.GroupAttribute,
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

		user, err := oa.ldapSRToUser(sr)

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
	return oa.ldapSRToUser(sr)
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

// ChangeLDAPPassword will attempt to change a user's password
func (oa *OutbackApp) ChangeLDAPPassword(user *LDAPUser, oldpwd string, password string) error {
	// Active Directory does not support the password modify extended request
	// so we must do it by modifying the unicodePwd attribute.
	// This must be done by setting it to "password" (with the quotes)
	// and encoding that with UTF-16 in Little Endian mode.

	// Yeah, seriously.
	if oa.Config.LDAPConfig.ActiveDirectory {
		enc := unicode.UTF16(unicode.LittleEndian, unicode.IgnoreBOM).NewEncoder()
		encoded, err := enc.String("\"" + password + "\"")
		if err != nil {
			return err
		}

		mod := ldap.NewModifyRequest(user.DN)
		mod.Replace("unicodePwd", []string{encoded})

		conn, err := oa.getLDAP(true)
		if err != nil {
			return err
		}

		err = conn.Modify(mod)
		if err != nil {
			if ldap.IsErrorWithCode(err, ldap.ErrorNetwork) {
				oa.ldap = nil
				return oa.ChangeLDAPPassword(user, oldpwd, password)
			}
			return err
		}

		return nil
	}

	var conn *ldap.Conn
	var err error
	var pwchange *ldap.PasswordModifyRequest

	if oa.Config.LDAPConfig.PasswordPolicy.UserChange {
		// bind and change as the user
		conn, err = oa.getLDAP(false)
		if err != nil {
			return err
		}
		err = conn.Bind(user.DN, oldpwd)
		if err != nil {
			return err
		}
		pwchange = ldap.NewPasswordModifyRequest("", oldpwd, password)
	} else {
		// change as the admin user
		conn, err = oa.getLDAP(true)
		if err != nil {
			return err
		}
		pwchange = ldap.NewPasswordModifyRequest(user.DN, "", password)
	}

	_, err = conn.PasswordModify(pwchange)
	if err != nil {
		return err
	}
	return nil
}

// MatchesPolicy confirms if a password meets the password policy
func (pp *passwordPolicyConfig) MatchesPolicy(pwd string) error {
	if len(pwd) < pp.MinLength {
		return errors.New("must be at least " + strconv.Itoa(pp.MinLength) + " characters")
	}
	if pp.Capitals && strings.ToLower(pwd) == pwd {
		return errors.New("must contain at least one (1) uppercase character")
	}
	if pp.Numbers && !strings.ContainsAny(pwd, "0123456789") {
		return errors.New("must contain at least one (1) number")
	}
	if pp.Symbols && !strings.ContainsAny(pwd, "`~!@#$%^&*()-_=+[{]}\\|;:'\"/?.>,<") {
		return errors.New("must contain at least one (1) symbol")
	}
	return nil
}

func (oa *OutbackApp) niceLDAPError(err error) string {
	ldapErr, ok := err.(*ldap.Error)
	if !ok {
		return err.Error()
	}
	result, ok := ldap.LDAPResultCodeMap[ldapErr.ResultCode]
	if !ok {
		return "unknown LDAP error: " + strconv.Itoa(int(ldapErr.ResultCode))
	}
	return result
}
