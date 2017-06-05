package outback

import (
	"io"
	"net/http"
)

func (oa *OutbackApp) RenderTemplate(tmpl string, w io.Writer, data interface{}) error {
	return oa.render.HTML(w, http.StatusOK, tmpl, data)
	//return oa.templates.Lookup(tmpl).ExecuteTemplate(w, "base.html", data)
}
