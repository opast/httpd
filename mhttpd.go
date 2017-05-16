package main

import (
	"html/template"
	"net/http"

	"fmt"
	"github.com/gorilla/context"
	"github.com/gorilla/sessions"
	"os/exec"
	"io"
	"log"
)

type user struct {
	Login    string
	Password string
}

var (
	store  = sessions.NewCookieStore([]byte("33446a9dcf9ea060a0a6532b166da32f304af0de"))
	userdb user
	tpl    *template.Template
)

func index(w http.ResponseWriter, req *http.Request) {
	logFunc("Host " + req.RemoteAddr + " visited /")

	tpl.ExecuteTemplate(w, "index.html", nil)
}

func do(w http.ResponseWriter, req *http.Request) {
	logFunc("Host " + req.RemoteAddr + " visited /do")

	if !alreadyLoggedIn(w, req) {
//		http.Redirect(w, req, "/login", http.StatusSeeOther)
		return
	}

	// process form submission
	if req.Method == http.MethodPost {
		hostname := req.FormValue("hostname")
		ipaddress := req.FormValue("ipaddress")

		fmt.Println(hostname, ipaddress)

		arg := "-l"

		out, _ := exec.Command("ls", arg).Output()

		io.WriteString(w, fmt.Sprintf("%s", out))
//		print(str)
//		http.Redirect(w, req, "/done", http.StatusSeeOther)

		return
	}

	tpl.ExecuteTemplate(w, "do.html", nil)
}

func done(w http.ResponseWriter, req *http.Request) {
	logFunc("Host " + req.RemoteAddr + " visited /done")

	if !alreadyLoggedIn(w, req) {
//		http.Redirect(w, req, "/login", http.StatusSeeOther)
		return
	}

	tpl.ExecuteTemplate(w, "done.html", nil)
}

func login(w http.ResponseWriter, req *http.Request) {
	logFunc("Host " + req.RemoteAddr + " visited /login")

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
	logFunc("Host " + req.RemoteAddr + " visited /logout")
	session, _ := store.Get(req, "session")

	// Revoke users authentication
	session.Values["username"] = ""
	session.Save(req, w)

	http.Redirect(w, req, "/login", http.StatusSeeOther)
}

func alreadyLoggedIn(w http.ResponseWriter, req *http.Request) bool {
	session, err := store.Get(req, "session")
	if err != nil {
		http.Redirect(w, req, "/", http.StatusSeeOther)
		return false
	}

	username, found := session.Values["username"]
	if !found || username == "" {
		http.Redirect(w, req, "/login", http.StatusSeeOther)
		return false
	}

	return true
}

func main() {

	userdb.Login = "opast"
	userdb.Password = "123456"

	store.Options = &sessions.Options{
//		Domain:   "localhost",
		Path:     "/",
		MaxAge:   10 * 30,
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

	http.ListenAndServeTLS(":8443", "cert.pem", "key.pem", context.ClearHandler(http.DefaultServeMux))
}

func logFunc(l string) {
	log.Println(l)
}
