package api

import (
	"github.com/ImageWare/TLSential/auth"
	"github.com/ImageWare/TLSential/model"
	"github.com/ImageWare/TLSential/repository/boltdb"
	"github.com/ImageWare/TLSential/service"
	"github.com/boltdb/bolt"

	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAuthenticateHandler(t *testing.T) {
	db, err := bolt.Open(".test.db", 0666, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	repo, err := boltdb.NewUserRepository(db)
	if err != nil {
		t.Fatal(err)
	}

	us := service.NewUserService(repo)

	router := testRouter(t, us)

	u, err := model.NewUser("test-name", "test-password", auth.RoleUserReader)
	if err != nil {
		t.Fatal(err)
	}

	repo.SaveUser(u)

	// FAIL
	t.Run("Bad Header Format 1", func(t *testing.T) {
		req, err := http.NewRequest("POST", "/api/authenticate", nil)
		if err != nil {
			t.Fatal(err)
		}

		req.Header.Set("Authorization", "nospaces")

		testRequest(t, router, req, http.StatusBadRequest, ErrAuthFailed.Error())
	})

	// FAIL
	t.Run("Bad Header Format 2", func(t *testing.T) {
		req, err := http.NewRequest("POST", "/api/authenticate", nil)
		if err != nil {
			t.Fatal(err)
		}

		req.Header.Set("Authorization", "two spa ces")

		testRequest(t, router, req, http.StatusBadRequest, ErrAuthFailed.Error())
	})

	// FAIL
	t.Run("Bad Header Format 3", func(t *testing.T) {
		req, err := http.NewRequest("POST", "/api/authenticate", nil)
		if err != nil {
			t.Fatal(err)
		}

		// Test when "Basic" is not first word
		req.Header.Set("Authorization", "Blasic auth")

		testRequest(t, router, req, http.StatusBadRequest, ErrAuthFailed.Error())
	})

	// FAIL
	t.Run("Bad Base64", func(t *testing.T) {
		req, err := http.NewRequest("POST", "/api/authenticate", nil)
		if err != nil {
			t.Fatal(err)
		}

		req.Header.Set("Authorization", "Basic definitelynotbase64!")

		testRequest(t, router, req, http.StatusBadRequest, ErrAuthFailed.Error())
	})

	// FAIL
	t.Run("Bad Credential Format", func(t *testing.T) {
		req, err := http.NewRequest("POST", "/api/authenticate", nil)
		if err != nil {
			t.Fatal(err)
		}

		b := base64.StdEncoding.EncodeToString([]byte("nocolon"))
		v := fmt.Sprintf("Basic %s", b)
		req.Header.Set("Authorization", v)

		testRequest(t, router, req, http.StatusBadRequest, ErrAuthFailed.Error())
	})

	// FAIL
	t.Run("Bad Username", func(t *testing.T) {
		req, err := http.NewRequest("POST", "/api/authenticate", nil)
		if err != nil {
			t.Fatal(err)
		}

		b := base64.StdEncoding.EncodeToString([]byte("bad-name:bad-password"))
		v := fmt.Sprintf("Basic %s", b)
		req.Header.Set("Authorization", v)

		testRequest(t, router, req, http.StatusUnauthorized, ErrAuthFailed.Error())
	})

	// FAIL
	t.Run("Bad Password", func(t *testing.T) {
		req, err := http.NewRequest("POST", "/api/authenticate", nil)
		if err != nil {
			t.Fatal(err)
		}

		b := base64.StdEncoding.EncodeToString([]byte("test-name:bad-password"))
		v := fmt.Sprintf("Basic %s", b)
		req.Header.Set("Authorization", v)

		testRequest(t, router, req, http.StatusUnauthorized, ErrAuthInvalidCreds.Error())
	})

	// SUCCESS
	t.Run("Good Creds", func(t *testing.T) {
		req, err := http.NewRequest("POST", "/api/authenticate", nil)
		if err != nil {
			t.Fatal(err)
		}

		b := base64.StdEncoding.EncodeToString([]byte("test-name:test-password"))
		v := fmt.Sprintf("Basic %s", b)
		req.Header.Set("Authorization", v)

		rr := httptest.NewRecorder()

		router.ServeHTTP(rr, req)

		if status := rr.Code; status != http.StatusOK {
			t.Errorf("handler returned wrong status code:\n\tgot %v \n\twant %v",
				status, http.StatusOK)
		}
		t.Log(rr.Body.String())

	})

}
