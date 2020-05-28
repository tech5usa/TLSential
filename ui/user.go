package ui

import (
	"fmt"
	"html/template"
	"log"
	"net/http"

	"github.com/ImageWare/TLSential/model"
	"github.com/gorilla/csrf"
	"github.com/gorilla/mux"
)

// createUserTemplate holds variables for html template that renders the user create page.
type createUserTemplate struct {
	Name       string
	Role       string
	CSRFField  template.HTML
	Validation userValidation
}

// userValidation holds any UI error strings that will need to be rendered if Creation fails.
type userValidation struct {
	Name     string
	Role     string
	Password string
	Success  string
	Error    string
}

// Serve /ui/user/create page.
func (h *uiHandler) CreateUser() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" {
			uv := userValidation{}

			name := r.FormValue("name")
			role := r.FormValue("role")
			password := r.FormValue("password")

			existing, err := h.userService.GetUser(name)
			if err != nil {
				log.Print(err.Error())
				http.Error(w, "fools", http.StatusInternalServerError)
				return
			}
			if existing != nil {
				uv.Name = "User with that name already exists"
				uv.Error = "Fix invalid fields and try again."
				h.renderCreateUser(w, r, uv)
				return
			}

			// TODO: Validate role in create UI
			// TODO: Validate password in create UI

			user, err := model.NewUser(name, password, role)
			if err != nil {
				log.Print(err.Error())
				http.Error(w, "fools", http.StatusInternalServerError)
				return
			}

			err = h.userService.SaveUser(user)
			if err != nil {
				log.Print(err.Error())
				http.Error(w, "potatoes", http.StatusInternalServerError)
				return
			}

			http.Redirect(w, r, "/ui/user/id/"+user.Name, http.StatusSeeOther)
			return
		}
		h.renderCreateUser(w, r, userValidation{})
	}
}

func (h *uiHandler) renderCreateUser(w http.ResponseWriter, r *http.Request, uv userValidation) {
	t, err := template.ParseFiles("ui/templates/create_user.html")
	if err != nil {
		log.Print(err.Error())
		http.Error(w, "oh boyyyy :(", http.StatusInternalServerError)
		return
	}

	p := createUserTemplate{
		Name:       r.FormValue("name"),
		Role:       r.FormValue("role"),
		CSRFField:  csrf.TemplateField(r),
		Validation: uv,
	}

	err = renderLayout(t, "Create New User", p, w, r)
	if err != nil {
		log.Print(err.Error())
	}
}

// userTemplate holds the user variables being rendered for the html template.
type userTemplate struct {
	Name string
	Role string
}

// Serve /ui/user/id/{id} page.
func (h *uiHandler) ViewUser() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		t, err := template.ParseFiles("ui/templates/view_user.html")
		if err != nil {
			log.Print(err.Error())
			http.Error(w, "phooey", http.StatusInternalServerError)
			return
		}

		// aka "Name"
		id := mux.Vars(r)["id"]

		user, err := h.userService.GetUser(id)
		if err != nil {
			log.Print(err.Error())
			http.Error(w, "gee willikers", http.StatusInternalServerError)
			return
		}

		p := userTemplate{
			user.Name,
			user.Role,
		}

		err = renderLayout(t, fmt.Sprintf("User - %s", user.Name), p, w, r)
		if err != nil {
			log.Print(err.Error())
		}
	}
}

// Serve /ui/user/id/{id}/edit page.
// Cannot rename users
func (h *uiHandler) SaveUser() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		role := r.FormValue("role")

		id := mux.Vars(r)["id"]

		user, err := h.userService.GetUser(id)
		if err != nil {
			log.Print(err.Error())
			http.Error(w, "crududdle", http.StatusInternalServerError)
			return
		}

		uv := userValidation{}

		// TODO: Validate this is a valid role and can be created by someone
		// with current permissions
		user.Role = role

		h.userService.SaveUser(user)
		if err != nil {
			log.Print(err.Error())
			http.Error(w, "sh!t", http.StatusInternalServerError)
			return
		}

		uv.Success = "Successfully saved user."
		http.Redirect(w, r, "/ui/user/id/"+user.Name, http.StatusSeeOther)
	}
}

// editUserTemplate holds the variables for the html template that shows the user edit page.
type editUserTemplate struct {
	Name       string
	Role       string
	CSRFField  template.HTML
	Validation userValidation
}

// Serve /ui/user/id/{id}/edit page.
func (h *uiHandler) EditUser() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		uv := userValidation{}
		h.renderUser(w, r, uv)
	}
}

func (h *uiHandler) renderUser(w http.ResponseWriter, r *http.Request, uv userValidation) {
	t, err := template.ParseFiles("ui/templates/edit_user.html")
	if err != nil {
		log.Print(err.Error())
		http.Error(w, "turnips", http.StatusInternalServerError)
		return
	}

	id := mux.Vars(r)["id"]

	user, err := h.userService.GetUser(id)
	if err != nil {
		log.Print(err.Error())
		http.Error(w, "cowabunga", http.StatusInternalServerError)
		return
	}

	if user == nil {
		http.Error(w, "Not found.", http.StatusNotFound)
		return
	}

	p := editUserTemplate{
		Name:       user.Name,
		Role:       user.Role,
		CSRFField:  csrf.TemplateField(r),
		Validation: uv,
	}

	err = renderLayout(t, fmt.Sprintf("User - %s", user.Name), p, w, r)

	if err != nil {
		log.Print(err.Error())
	}
}

// userListTemplate holds all users for parsing into html template.
type userListTemplate struct {
	Users []*model.User
}

// Serve /ui/users page.
func (h *uiHandler) ListUsers() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {

		t, err := template.ParseFiles("ui/templates/users.html")
		if err != nil {
			log.Print(err.Error())
			http.Error(w, "golly gee", http.StatusInternalServerError)
			return
		}

		users, err := h.userService.GetAllUsers()
		if err != nil {
			log.Print(err.Error())
			http.Error(w, "phug", http.StatusInternalServerError)
			return
		}

		p := userListTemplate{
			users,
		}

		err = renderLayout(t, "Users", p, w, r)
		if err != nil {
			log.Print(err.Error())
		}
	}
}

// deleteUserTemplate holds variables for html template that renders the user delete page.
type deleteUserTemplate struct {
	Name      string
	CSRFField template.HTML
}

// Serve /ui/user/create page.
func (h *uiHandler) DeleteUser() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" {
			id := mux.Vars(r)["id"]
			err := h.userService.DeleteUser(id)
			if err != nil {
				log.Print(err.Error())
				http.Error(w, "crepes", http.StatusInternalServerError)
				return
			}

			http.Redirect(w, r, "/ui/users", http.StatusSeeOther)
			return
		}
		h.renderDeleteUser(w, r)
	}
}

func (h *uiHandler) renderDeleteUser(w http.ResponseWriter, r *http.Request) {

	t, err := template.ParseFiles("ui/templates/delete_user.html")
	if err != nil {
		log.Print(err.Error())
		http.Error(w, "fannies", http.StatusInternalServerError)
		return
	}

	id := mux.Vars(r)["id"]

	user, err := h.userService.GetUser(id)
	if err != nil {
		log.Print(err.Error())
		http.Error(w, "gosh darn", http.StatusInternalServerError)
		return
	}

	if user == nil {
		http.Error(w, "Not found.", http.StatusNotFound)
		return
	}

	p := deleteUserTemplate{
		Name:      id,
		CSRFField: csrf.TemplateField(r),
	}

	err = renderLayout(t, "Delete User", p, w, r)
	if err != nil {
		log.Print(err.Error())
	}
}
