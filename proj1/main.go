package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"golang.org/x/crypto/bcrypt"
)

var userMap = map[string]string{}
var sessionMap = map[string]string{}
var currentSessionID = 0

func main() {
	// createJWTToken("1")
	http.HandleFunc("/", index)
	http.HandleFunc("/login", login)
	http.HandleFunc("/authenticate", authenticate)
	http.HandleFunc("/home", home)

	http.HandleFunc("/register", register)

	http.ListenAndServe(":8090", nil)

}

// const lorem = `Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.`

var secret = []byte{'h', 'e', 'l', 'l', 'o'}

type MyCustomClaims struct {
	SessionID string `json:"sessionID"`
	jwt.RegisteredClaims
}

// var secret = make([]byte, 64)

func createToken(sessionID string) string {
	data := []byte(sessionID)
	mac := hmac.New(sha256.New, secret)
	mac.Write(data)
	hash_b := mac.Sum(nil)
	fmt.Println(len(hash_b))
	result := string(hash_b) + sessionID
	base64Signed := base64.URLEncoding.EncodeToString([]byte(result))
	return base64Signed
}

func parseToken(signedmsg string) (string, error) {
	val, err := base64.URLEncoding.DecodeString(signedmsg)
	if err != nil {
		return "", fmt.Errorf("failed to decode signed msg")
	}
	signedString := string(val)
	signature := signedString[:32]
	data := signedString[32:]
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(data))
	expectedSignature := mac.Sum(nil)
	if !hmac.Equal([]byte(signature), expectedSignature) {
		return "", fmt.Errorf("signatures do not match")
	}
	return data, nil
}

func home(w http.ResponseWriter, req *http.Request) {
	var username string
	cookie, err := req.Cookie("sessionID")
	if err == nil {
		sessionID, err := parseJWTToken(cookie.Value)
		if err != nil {
			username = "Not present"
		} else {
			username = sessionMap[sessionID]
		}
	}
	homepage := `<!DOCTYPE html>
	<html>
	<body>	
	<h2>Login successful</h2>
	<h3>Hi there %s</h3>
	</body>
	</html>
	`
	fmt.Fprintf(w, homepage, username)
}

func authenticate(w http.ResponseWriter, req *http.Request) {
	username := req.FormValue("username")
	password := req.FormValue("password")
	passhash, ok := userMap[username]
	if !ok {
		errormsg := url.QueryEscape("username does not exist")
		http.Redirect(w, req, "/login?errormsg="+errormsg, http.StatusSeeOther)
		return
	}
	err := bcrypt.CompareHashAndPassword([]byte(passhash), []byte(password))
	if err != nil {
		errormsg := url.QueryEscape("login failed")
		http.Redirect(w, req, "/login?errormsg="+errormsg, http.StatusSeeOther)
		return
	}
	sessionID := currentSessionID + 1
	sessionString := strconv.Itoa(sessionID)
	signedString := createJWTToken(sessionString)
	cookie := http.Cookie{
		Name:  "sessionID",
		Value: signedString,
	}
	http.SetCookie(w, &cookie)
	sessionMap[sessionString] = username
	currentSessionID = sessionID
	http.Redirect(w, req, "/home", http.StatusSeeOther)
}

func login(w http.ResponseWriter, req *http.Request) {
	errorMsg := req.FormValue("errormsg")
	loginForm := `<!DOCTYPE html>
	<html>
	<body>
	
	<h2>Login</h2>
	<p><b>%s</b></p>
	<form action="/authenticate" method="POST">
	  <label for="username">Username:</label><br>
	  <input type="text" id="username" name="username"><br>
	  <label for="password">Password:</label><br>
	  <input type="text" id="password" name="password"><br><br>
	  <input type="submit" value="Submit">
	</form> 
	
	
	</body>
	</html>
	`
	fmt.Fprintf(w, loginForm, errorMsg)
}

func index(w http.ResponseWriter, req *http.Request) {
	var username string
	cookie, err := req.Cookie("sessionID")
	if err == nil {
		sessionID, err := parseJWTToken(cookie.Value)
		if err != nil {
			username = "Not present"
		} else {
			username = sessionMap[sessionID]
		}
	}
	registerForm := `<!DOCTYPE html>
	<html>
	<body>
	<h2>Hi there %s</h2>
	<h2>Register</h2>
	
	<form action="/register" method="POST">
	  <label for="username">Username:</label><br>
	  <input type="text" id="username" name="username"><br>
	  <label for="password">Password:</label><br>
	  <input type="text" id="password" name="password"><br><br>
	  <input type="submit" value="Submit">
	</form> 
	
	
	</body>
	</html>
	`
	fmt.Fprintf(w, registerForm, username)
}

func register(w http.ResponseWriter, req *http.Request) {
	username := req.FormValue("username")
	password := req.FormValue("password")
	password_hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
	if err != nil {
		fmt.Println(err)
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("500-Something bad happened"))
		return
	}
	userMap[username] = string(password_hash)
	fmt.Print(userMap)
	// Generate session
	sessionID := currentSessionID + 1
	sessionString := strconv.Itoa(sessionID)
	signedString := createJWTToken(sessionString)
	cookie := http.Cookie{
		Name:  "sessionID",
		Value: signedString,
	}
	http.SetCookie(w, &cookie)
	sessionMap[sessionString] = username
	currentSessionID = sessionID
	http.Redirect(w, req, "/", http.StatusSeeOther)
}

func createJWTToken(sessionID string) string {
	claims := MyCustomClaims{
		sessionID,
		jwt.RegisteredClaims{
			// Also fixed dates can be used for the NumericDate
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(1 * time.Minute)),
			Issuer:    "test",
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	ss, err := token.SignedString(secret)
	fmt.Println(ss, err)
	return ss
}

func parseJWTToken(signedMsg string) (string, error) {
	token, err := jwt.ParseWithClaims(signedMsg, &MyCustomClaims{}, func(token *jwt.Token) (interface{}, error) {
		return secret, nil
	})
	if err != nil {
		return "", fmt.Errorf("failed to validate JWT token due to %s", err)
	} else if claims, ok := token.Claims.(*MyCustomClaims); ok {
		return claims.SessionID, nil
	} else {
		return "", fmt.Errorf("unknown claims type: %v", claims)
	}
}
