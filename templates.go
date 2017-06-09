package outback

import (
	"io"
	"net/http"
)

func (oa *OutbackApp) RenderTemplate(tmpl string, w io.Writer, data interface{}) error {
	return oa.render.HTML(w, http.StatusOK, tmpl, data)
	//return oa.templates.Lookup(tmpl).ExecuteTemplate(w, "base.html", data)
}

func (oa *OutbackApp) RenderTemplateStatus(tmpl string, stat int, w io.Writer, data interface{}) error {
	return oa.render.HTML(w, stat, tmpl, data)
}

type SAMLTemplateProvider struct {
	oa *OutbackApp
}

func (stp *SAMLTemplateProvider) MakeHTTPPostTemplate(w http.ResponseWriter, url string, samlResponse string, relayState string) error {
	return stp.oa.RenderTemplate("saml_redirect", w, struct {
		URL          string
		SAMLResponse string
		RelayState   string
	}{
		URL:          url,
		SAMLResponse: samlResponse,
		RelayState:   relayState,
	})
}
