package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/google/uuid"
	"github.com/xyproto/randomstring"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/amazon"
)

var amazonOauthConfig = oauth2.Config{
	ClientID:     "amzn1.application-oa2-client.93b5d3075e2c4551a3d7995c91dcd828",
	ClientSecret: "amzn1.oa2-cs.v1.7be2b3b17aa521933327ef98f92ed31697a8fe9833a3523ea12d40deae055dc5",
	Endpoint:     amazon.Endpoint,
	RedirectURL:  "http://localhost:8090/oauth/receive",
	Scopes:       []string{"profile:user_id", "profile:email"},
}

var stateMap = map[string]time.Time{}
var oauthConnections = map[string]string{}
var secret = []byte{'h', 'e', 'l', 'l', 'o'}
var sessionMap = map[string]string{}

type MyCustomClaims struct {
	SessionID string `json:"sessionID"`
	jwt.RegisteredClaims
}

type amazonUserData struct {
	UserID string `json:"user_id"`
	Email  string `json:"email"`
}

func main() {
	http.HandleFunc("/", index)
	http.HandleFunc("/oauth/login", loginoauth)
	http.HandleFunc("/oauth/receive", logincallback)
	http.HandleFunc("/partial-register", partialregister)

	http.ListenAndServe(":8090", nil)

}

func index(w http.ResponseWriter, req *http.Request) {
	var email string
	cookie, err := req.Cookie("sessionID")
	if err == nil {
		sessionID, err := parseJWTToken(cookie.Value)
		if err != nil {
			email = "Not present"
		} else {
			email = sessionMap[sessionID]
		}
	}
	loginForm := `<!DOCTYPE html>
	<html>
	<body>	
	<h2>Login</h2>
	<h2>Hi there %s<h2>
	<form action="/oauth/login" method="POST">
	  <input type="submit" value="Login via Amazon">
	</form>
	</body>
	</html>
	`
	fmt.Fprintf(w, loginForm, email)
}

func loginoauth(w http.ResponseWriter, req *http.Request) {
	id := uuid.New()
	state := id.String()
	expiryTime := time.Now().Add(1 * time.Hour)
	stateMap[state] = expiryTime
	http.Redirect(w, req, amazonOauthConfig.AuthCodeURL(state), http.StatusSeeOther)
}

func logincallback(w http.ResponseWriter, req *http.Request) {
	state := req.FormValue("state")
	code := req.FormValue("code")
	expirytime := stateMap[state]
	if time.Now().After(expirytime) {
		http.Error(w, "Login expired", http.StatusInternalServerError)
		return
	}
	token, err := amazonOauthConfig.Exchange(req.Context(), code)
	if err != nil {
		http.Error(w, "Failed to get token", http.StatusInternalServerError)
		return
	}

	tokenSource := amazonOauthConfig.TokenSource(req.Context(), token)

	client := oauth2.NewClient(req.Context(), tokenSource)

	resp, err := client.Get("https://api.amazon.com/user/profile")
	if err != nil {
		log.Println("Error on response.\n[ERROR] -", err)
	}
	defer resp.Body.Close()

	// body, err := ioutil.ReadAll(resp.Body)
	// if err != nil {
	// 	log.Println("Error while reading the response bytes:", err)
	// }
	// log.Println(string([]byte(body)))
	var userData amazonUserData
	// w.Write([]byte(body))
	err = json.NewDecoder(resp.Body).Decode(&userData)
	if err != nil {
		http.Error(w, "Failed to decode response", http.StatusInternalServerError)
		return
	}
	log.Println(userData.UserID)
	if _, ok := oauthConnections[userData.UserID]; !ok {
		appUserID := randomstring.CookieFriendlyString(5)
		oauthConnections[userData.UserID] = appUserID
	}
	// appUserID := oauthConnections[userData.UserID]
	signeduserID := createJWTToken(userData.UserID)
	cookie := http.Cookie{
		Name:  "sessionID",
		Value: signeduserID,
		Path:  "/",
	}
	http.SetCookie(w, &cookie)
	sessionMap[userData.UserID] = userData.Email
	params := url.Values{}
	params.Add("signeduserid", signeduserID)
	params.Add("email", userData.Email)
	http.Redirect(w, req, "/partial-register?"+params.Encode(), http.StatusFound)

}

func partialregister(w http.ResponseWriter, req *http.Request) {
	fmt.Println(req.URL.Query())
	w.Write([]byte("Hello"))
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
		fmt.Println(claims.SessionID)
		return claims.SessionID, nil
	} else {
		return "", fmt.Errorf("unknown claims type: %v", claims)
	}
}
