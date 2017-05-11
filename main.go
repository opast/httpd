package mhttpd

import (
	"html/template"
	"net/http"

	"github.com/gorilla/sessions"
	"fmt"
	"os/exec"
)

var tpl *template.Template

type user struct {
	Login    string
	Password string
}

var store = sessions.NewCookieStore([]byte("33446a9dcf9ea060a0a6532b166da32f304af0de"))

var userdb user

func index(w http.ResponseWriter, req *http.Request) {

	tpl.ExecuteTemplate(w, "index.html", nil)
}

func do(w http.ResponseWriter, req *http.Request) {
	session, err := store.Get(req, "session")
	if err != nil {
		http.Redirect(w, req, "/", http.StatusSeeOther)
		return
	}

	username, found := session.Values["username"]
	if !found || username == "" {
		http.Redirect(w, req, "/login", http.StatusSeeOther)
		return
	}

	// process form submission
	if req.Method == http.MethodPost {
		hostname := req.FormValue("hostname")
		ipaddress := req.FormValue("ipaddress")

		fmt.Println(hostname, ipaddress)

		arg := "-l"

		out, _ := exec.Command("ls", arg).Output()

		fmt.Printf("%s\n\n",out)


		http.Redirect(w, req, "/done", http.StatusSeeOther)
		return
	}

	tpl.ExecuteTemplate(w, "do.html", nil)
}

func done(w http.ResponseWriter, req *http.Request) {
	session, err := store.Get(req, "session")
	if err != nil {
		http.Redirect(w, req, "/", http.StatusSeeOther)
		return
	}

	username, found := session.Values["username"]
	if !found || username == "" {
		http.Redirect(w, req, "/login", http.StatusSeeOther)
		return
	}

	tpl.ExecuteTemplate(w, "done.html", nil)
}

func login(w http.ResponseWriter, req *http.Request) {
	session, err := store.Get(req, "session")
	if err != nil {
		http.Redirect(w, req, "/", http.StatusSeeOther)
		return
	}

	// process form submission
	if req.Method == http.MethodPost {
		un := req.FormValue("username")
		p := req.FormValue("password")
		// is there a username?

		if un != userdb.Login && p != userdb.Password {
			http.Error(w, "Username and/or password do not match", http.StatusForbidden)
			return
		}

		// Set user as authenticated
		session.Values["username"] = un
		session.Save(req, w)

		http.Redirect(w, req, "/", http.StatusSeeOther)
		return
	}

	tpl.ExecuteTemplate(w, "login.html", nil)
}

func logout(w http.ResponseWriter, req *http.Request) {
	session, _ := store.Get(req, "session")

	// Revoke users authentication
	session.Values["username"] = ""
	session.Save(req, w)

	http.Redirect(w, req, "/login", http.StatusSeeOther)
}

func main() {

	userdb.Login = "opast"
	userdb.Password = "123456"

	store.Options = &sessions.Options{
		Domain:   "localhost",
		Path:     "/",
		MaxAge:   60 * 15,
		Secure:   true,
		HttpOnly: true,
	}

	tpl = template.Must(template.ParseGlob("templates/*"))

	http.HandleFunc("/", index)
	http.HandleFunc("/do", do)
	http.HandleFunc("/done", done)
	http.HandleFunc("/login", login)
	http.HandleFunc("/logout", logout)
	http.Handle("/favicon.ico", http.NotFoundHandler())

	http.ListenAndServeTLS(":8443", "cert.pem", "key.pem", nil)
}
