package outback

import (
	"io/ioutil"
	"path"
	"plugin"

	"strings"

	log "github.com/Sirupsen/logrus"
	"github.com/parryjacob/saml"
)

type pluginManager struct {
	Plugins          map[string]*plugin.Plugin
	AttributePlugins map[string]func(*LDAPUser, *saml.EntityDescriptor) ([]saml.Attribute, error)
	AssertionPlugins map[string]func(*LDAPUser, *saml.EntityDescriptor, *saml.Assertion) error
}

func (oa *OutbackApp) loadPlugins(configDir string) error {
	log.Debug("Loading plugins...")

	plugMan := &pluginManager{
		Plugins:          map[string]*plugin.Plugin{},
		AttributePlugins: map[string]func(*LDAPUser, *saml.EntityDescriptor) ([]saml.Attribute, error){},
		AssertionPlugins: map[string]func(*LDAPUser, *saml.EntityDescriptor, *saml.Assertion) error{},
	}

	files, err := ioutil.ReadDir(configDir)
	if err != nil {
		return err
	}
	for _, f := range files {
		if f.IsDir() {
			continue
		}
		if strings.HasSuffix(strings.ToLower(f.Name()), ".so") {
			pgName := f.Name()
			fn := path.Join(configDir, pgName)

			pg, err := plugin.Open(fn)
			if err != nil {
				log.WithError(err).Errorf("Failed to load plugin %s!", pgName)
				continue
			}

			log.Debugf("Loading plugin %s...", pgName)

			// check for init method
			if initsym, err := pg.Lookup("Initialize"); err == nil {
				fnc, ok := initsym.(func(*OutbackApp, string) error)
				if !ok {
					log.Errorf("Invalid function descriptor for Initialize in %s", pgName)
				} else {
					if err := fnc(oa, pgName); err != nil {
						log.WithError(err).Errorf("Failed to initialize plugin %s, skipping", pgName)
						continue
					}
				}
			}

			plugMan.Plugins[pgName] = pg
		}
	}

	oa.pluginManager = plugMan

	return nil
}

func (pm *pluginManager) findPluginMethods() error {
	for pgName, pg := range pm.Plugins {
		// does it handle attributes?
		if attrfnc, err := pg.Lookup("AlterAttributes"); err == nil {
			fnc, ok := attrfnc.(func(*LDAPUser, *saml.EntityDescriptor) ([]saml.Attribute, error))
			if !ok {
				log.Errorf("Invalid function descriptor for AlterAttributes in %s", pgName)
			} else {
				pm.AttributePlugins[pgName] = fnc
				log.Debugf("Registering AlterAttributes handler for %s", pgName)
			}
		}

		// does it mutate assertions
		if asfnc, err := pg.Lookup("AlterAssertion"); err == nil {
			fnc, ok := asfnc.(func(*LDAPUser, *saml.EntityDescriptor, *saml.Assertion) error)
			if !ok {
				log.Errorf("Invalid function descriptor for AlterAssertion in %s", pgName)
			} else {
				pm.AssertionPlugins[pgName] = fnc
				log.Debugf("Registering AlterAssertion handler for %s", pgName)
			}
		}
	}

	return nil
}
