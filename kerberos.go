package outback

import (
	"fmt"
	"path/filepath"

	"os"

	"net/http"

	"strings"

	log "github.com/Sirupsen/logrus"
	"github.com/apcera/gssapi"
	"github.com/apcera/gssapi/spnego"
)

func (oa *OutbackApp) initKerberos() error {
	log.Debug("Initializing Kerberos...")

	keytab, err := filepath.Abs(oa.Config.KerberosConfig.Keytab)
	if err != nil {
		return fmt.Errorf("could not find keytab: %s", err.Error())
	}
	log.Debugf("Kerberos using keytab %s", keytab)

	if err := os.Setenv("KRB5_KTNAME", keytab); err != nil {
		return err
	}

	opts := &gssapi.Options{
		LoadDefault: gssapi.MIT,
		Printers: []gssapi.Printer{
			log.New(),
		},
	}

	lib, err := gssapi.Load(opts)
	if err != nil {
		return fmt.Errorf("error loading kerberos: %s", err.Error())
	}

	// get the credential
	cred, mechs, _, err := lib.AcquireCred(lib.GSS_C_NO_NAME(), gssapi.GSS_C_INDEFINITE, lib.GSS_C_NO_OID_SET, gssapi.GSS_C_ACCEPT)
	defer mechs.Release()
	if err != nil {
		return fmt.Errorf("failed to get kerberos credentials: %s", err.Error())
	}

	oa.kerbLib = lib
	oa.kerbCred = cred

	return nil
}

func (oa *OutbackApp) shouldAttemptSPNEGO(r *http.Request) bool {
	if len(oa.Config.KerberosConfig.intranetAddr) == 0 {
		return true
	}

	rAddr := oa.remoteAddr(r)

	// Check if we're coming through a NAT gateway, which we should disallow
	for _, gw := range oa.Config.KerberosConfig.natAddrs {
		if gw.Equal(rAddr) {
			return false
		}
	}

	// Otherwise, allow from any intranet subnet
	for _, subnet := range oa.Config.KerberosConfig.intranetAddr {
		if subnet.Contains(rAddr) {
			return true
		}
	}

	return false
}

func (oa *OutbackApp) attemptSPNEGO(w http.ResponseWriter, r *http.Request) (*LDAPUser, error) {
	negotiate, inputToken := spnego.CheckSPNEGONegotiate(oa.kerbLib, r.Header, "Authorization")
	if !negotiate || inputToken.Length() == 0 {

		if oa.shouldAttemptSPNEGO(r) {

			if oa.Config.Debug {
				rAddr := oa.remoteAddr(r)
				log.Debugf("Enabling SPNEGO for connection from recognized intranet IP %s", rAddr.String())
			}

			spnego.AddSPNEGONegotiate(w.Header(), "WWW-Authenticate", nil)
		}

		return nil, nil
	}

	log.Debugf("Attempting SPNEGO authentication from %s", oa.remoteAddr(r).String())

	_, srcName, _, _, _, _, delegated, err := oa.kerbLib.AcceptSecContext(oa.kerbLib.GSS_C_NO_CONTEXT,
		oa.kerbCred, inputToken, oa.kerbLib.GSS_C_NO_CHANNEL_BINDINGS)

	if err != nil {
		if strings.EqualFold(strings.TrimSpace(err.Error()), "an unsupported mechanism was requested") {
			log.Debug("Client fallback to NTLM likely, rejecting")
			return nil, nil
		}
		return nil, err
	}

	defer srcName.Release()
	defer delegated.Release()

	// Returning this can cause errors, therefore we don't do it.
	//log.Debug("Sending return SPNEGO header")
	//spnego.AddSPNEGONegotiate(w.Header(), "WWW-Authenticate", outputToken)

	username := srcName.String()
	log.Debugf("SPNEGO returned principal %s", username)

	if !strings.HasSuffix(strings.ToLower(username),
		strings.ToLower("@"+oa.Config.KerberosConfig.Realm)) {
		log.Errorf("SPNEGO resulted in user with unkown realm: %s", username)
		return nil, fmt.Errorf("unknown realm for user %s", username)
	}

	username = username[:len(username)-len(oa.Config.KerberosConfig.Realm)-1]

	user, err := oa.FindLDAPUser(username)
	if user == nil && err == nil {
		log.Debugf("Could not find Kerberos negotiated user '%s' in LDAP", username)
	}

	return user, err
}
