package outback

import (
	"net/http"

	log "github.com/Sirupsen/logrus"
)

func (oa *OutbackApp) httpSSChangePassword(w http.ResponseWriter, r *http.Request) {
	session := oa.GetOutbackSession(w, r, nil)
	if session == nil {
		return
	}

	if r.Method == "POST" && r.PostForm.Get("pw_original") != "" {
		originalPassword := r.PostForm.Get("pw_original")
		newPassword := r.PostForm.Get("pw_new")

		if newPassword == originalPassword {
			oa.sendChangePasswordForm(w, r, "Passwords must not match")
			return
		}

		pwok, err := oa.TestLDAPUserPassword(session.ldapUser, originalPassword)
		if err != nil {
			oa.sendChangePasswordForm(w, r, "Error checking existing password")
			log.WithError(err).Error("Error checking existing password")
			return
		}

		if !pwok {
			oa.sendChangePasswordForm(w, r, "Wrong password")
			return
		}

		if err := oa.Config.LDAPConfig.PasswordPolicy.MatchesPolicy(newPassword); err != nil {
			oa.sendChangePasswordForm(w, r, "Password "+err.Error())
			return
		}

		if err := oa.ChangeLDAPPassword(session.ldapUser, originalPassword, newPassword); err != nil {
			oa.sendChangePasswordForm(w, r, "Could not change password: "+oa.niceLDAPError(err))
			log.WithError(err).Error("Failed to change password")
			return
		}

		// password changed
		if err := session.Destroy(oa, w, r); err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			log.WithError(err).Error("Failed to destroy session after changing password")
			return
		}

		// session is destroyed
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}

	oa.sendChangePasswordForm(w, r, "")
}

func (oa *OutbackApp) sendChangePasswordForm(w http.ResponseWriter, r *http.Request, msg string) {
	if err := oa.templates.Lookup("change_password.html").Execute(w, struct {
		Message string
		URL     string
	}{
		Message: msg,
		URL:     r.URL.String(),
	}); err != nil {
		panic(err)
	}
}
