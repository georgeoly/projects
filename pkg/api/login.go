package api

import (
	"net/url"
	"github.com/grafana/grafana/pkg/bus"
	"github.com/grafana/grafana/pkg/log"
	"github.com/grafana/grafana/pkg/middleware"
	m "github.com/grafana/grafana/pkg/models"
	"github.com/grafana/grafana/pkg/setting"
	"github.com/grafana/grafana/pkg/util"
  "net/http"
  "errors"
  "io/ioutil"
  "encoding/xml"
  "time"
"github.com/dgrijalva/jwt-go"
  "fmt"
)

const (
	VIEW_INDEX = "index"
)

func LoginView(c *middleware.Context) {
	viewData, err := setIndexViewData(c)
	if err != nil {
		c.Handle(500, "Failed to get settings", err)
		return
	}

	viewData.Settings["googleAuthEnabled"] = setting.OAuthService.Google
	viewData.Settings["githubAuthEnabled"] = setting.OAuthService.GitHub
  viewData.Settings["lottosAuthEnabled"] = setting.OAuthService.Lottos
	viewData.Settings["disableUserSignUp"] = true  //!setting.AllowUserSignUp
	viewData.Settings["loginHint"]         = false //setting.LoginHint

	if !tryLoginUsingRememberCookie(c) {
		c.HTML(200, VIEW_INDEX, viewData)
		return
	}

	if redirectTo, _ := url.QueryUnescape(c.GetCookie("redirect_to")); len(redirectTo) > 0 {
		c.SetCookie("redirect_to", "", -1, setting.AppSubUrl+"/")
		c.Redirect(redirectTo)
		return
	}

	c.Redirect(setting.AppSubUrl + "/")
}

func tryLoginUsingRememberCookie(c *middleware.Context) bool {
  // Check auto-login.
  uname := c.GetCookie(setting.CookieUserName)
  if len(uname) == 0 {
    return false
  }

  isSucceed := false
  defer func() {
    if !isSucceed {
      log.Trace("auto-login cookie cleared: %s", uname)
      c.SetCookie(setting.CookieUserName, "", -1, setting.AppSubUrl+"/")
      c.SetCookie(setting.CookieRememberName, "", -1, setting.AppSubUrl+"/")
      return
    }
  }()

  userQuery := m.GetUserByLoginQuery{LoginOrEmail: uname}
  if err := bus.Dispatch(&userQuery); err != nil {
    return false
  }

  user := userQuery.Result

  // validate remember me cookie
  if val, _ := c.GetSuperSecureCookie(
    util.EncodeMd5(user.Rands+user.Password), setting.CookieRememberName); val != user.Login {
    return false
  }

  isSucceed = true
  loginUserWithUser(user, c)
  return true
}


func LoginApiPing(c *middleware.Context) {
	if !tryLoginUsingRememberCookie(c) {
		c.JsonApiErr(401, "Unauthorized", nil)
		return
	}

	c.JsonOK("Logged in")
}

func LoginPost(c *middleware.Context) {

  log.Info("login.go ::: Entered LoginPost")

  if initContextWithAuthProxy(c) {
    c.Redirect(setting.AppSubUrl + "/")
    return
  }

  c.Handle(500, "Failed to get settings", errors.New("Error"))
}

func loginUserWithUser(user *m.User, c *middleware.Context) {
	if user == nil {
		log.Error(3, "User login with nil user")
	}

	days := 86400 * setting.LogInRememberDays
	c.SetCookie(setting.CookieUserName, user.Login, days, setting.AppSubUrl+"/")
	c.SetSuperSecureCookie(util.EncodeMd5(user.Rands+user.Password), setting.CookieRememberName, user.Login, days, setting.AppSubUrl+"/")

	c.Session.Set(middleware.SESS_KEY_USERID, user.Id)
}

func Logout(c *middleware.Context) {
	c.SetCookie(setting.CookieUserName, "", -1, setting.AppSubUrl+"/")
	c.SetCookie(setting.CookieRememberName, "", -1, setting.AppSubUrl+"/")
	c.Session.Destory(c)
	c.Redirect( setting.AuthProxyLogoutUrl )
}








func initContextWithAuthProxy(ctx *middleware.Context) bool {

  log.Debug("login.go ::: entered method")

  proxyHeaderValue := ctx.Req.Header.Get(setting.AuthProxyHeaderName)

  if len ( proxyHeaderValue ) == 0 {
    log.Debug("login.go ::: try getting from html post data")
    proxyHeaderValue = ctx.Req.FormValue(setting.AuthProxyHeaderName)
    log.Debug("login.go ::: reading proxyHeaderValue from form returning %v", proxyHeaderValue)

    ctx.Req.Header.Set(setting.AuthProxyHeaderName, proxyHeaderValue)

    log.Debug("login.go ::: setting setting HEADER %v with %v", setting.AuthProxyHeaderName, proxyHeaderValue)
  }

  log.Debug("login.go ::: reading proxyHeaderValue returning %v", proxyHeaderValue)

  if len(proxyHeaderValue) == 0 {
    log.Info("login.go ::: proxyHeaderValue returned null")

    http.Redirect(ctx.Resp, ctx.Req.Request, setting.AuthProxyLoginUrl, http.StatusFound)

    return false
  }

  retrievedKey, publickey := getKeyFromURL()

  if !retrievedKey {
    log.Info("login.go ::: NO RETRIEVED KEY")
    //TODO: Redirect or Access is denied
    return false
  }

  log.Debug("login.go ::: Retrieved Key %v", publickey)


  valid, username, authorities := isValidToken(proxyHeaderValue, publickey)

  if ( !valid ) {
    log.Debug("login.go ::: isValidToken returning %v", valid)

    ctx.Handle(401, "Access is denied", errors.New("Access is denied"))
    return false
  }

  log.Debug("login.go ::: going to validate username %v and authorities %v", username, authorities)


  if authorities == nil {

    var errorMessage string = "Unknown authorities returned"
    var errorR       error  = errors.New( errorMessage )

    log.Error (500, errorMessage, errorR)

    ctx.Handle(500, errorMessage, errorR )

    return true

  }

  found, query := getUserFromAuthorities(authorities)

  log.Debug("login.go ::: getUserFromAuthorities returning found=%v query=%v", found, query)

  if ( !found ) {

    var errorMessage string = "Failed find user specifed in auth proxy header"
    var errorR       error  = errors.New( errorMessage )

    log.Error (500, errorMessage, errorR)

    ctx.Handle(500, errorMessage, errorR )

    return true
  } else {
    log.Debug("login.go ::: found user query=%v", query)
  }

  log.Debug("login.go ::: before initialize session %v", username)

  // initialize session
  if err := ctx.Session.Start(ctx); err != nil {
    log.Error(3, "Failed to start session", err)
    return false
  }

  log.Debug("login.go ::: after initialize session %v", username)

  query.Result.PsevdoUsername = username

  ctx.SignedInUser    = query.Result
  ctx.PsevdoUsername  = username
  ctx.IsSignedIn      = true
  ctx.Session.Set(middleware.SESS_KEY_USERID, ctx.UserId)

  user := query.Result

  days := 86400 * setting.LogInRememberDays
  ctx.SetCookie(setting.CookieUserName, user.Login, days, setting.AppSubUrl+"/")
  //c.SetSuperSecureCookie(util.EncodeMd5(user.Rands+user.Password), setting.CookieRememberName, user.Login, days, setting.AppSubUrl+"/")

  ctx.Session.Set(middleware.SESS_KEY_USERID, user.UserId)

  return true
}

func getKeyFromURL() (bool, string) {

  resp, err := http.Get( setting.AuthProxyPublicKey )

  if err != nil {
    // handle error
    log.Debug("login.go ::: getKeyFromURL() error retrieving key from get %v", err)
    return false, ""
  }

  defer resp.Body.Close()

  body, err := ioutil.ReadAll(resp.Body)

  if err != nil {
    // handle error
    log.Debug("login.go ::: getKeyFromURL() error retrieving key, error reading body %v", err)
    return false, ""
  }

  //  body := "<Map><alg>SHA256withRSA</alg><value>-----BEGIN PUBLIC KEY-----\n" +
  //  "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnGp/Q5lh0P8nPL21oMMrt2RrkT9AW5jgYwLfSUnJVc9G6uR3cXRRDCjHqWU5WYwivcF180A6CWp/ireQFFBNowgc5XaA0kPpzEtgsA5YsNX7iSnUibB004iBTfU9hZ2Rbsc8cWqynT0RyN4TP1RYVSeVKvMQk4GT1r7JCEC+TNu1ELmbNwMQyzKjsfBXyIOCFU/E94ktvsTZUHF4Oq44DBylCDsS1k7/sfZC2G5EU7Oz0mhG8+Uz6MSEQHtoIi6mc8u64Rwi3Z3tscuWG2ShtsUFuNSAFNkY7LkLn+/hxLCu2bNISMaESa8dG22CIMuIeRLVcAmEWEWH5EEforTg+QIDAQAB\n" +
  //  "-----END PUBLIC KEY-----</value></Map>"

  type Map struct {
    Key []string `xml:"value"`
  }

  v := Map{Key: []string{}}

  err = xml.Unmarshal([]byte(body), &v)

  if err != nil {
    log.Debug("login.go ::: error while unmarshalling %v", err)
    return false, ""
  }

  log.Debug("login.go ::: Unmarshalled xml %q", v)

  if len( v.Key ) == 0 {
    log.Debug("login.go ::: NO keys found")
    return false, ""

  }

  return true, v.Key[0]
}

func getUserFromAuthorities( authorities interface{} ) (bool, *m.GetSignedInUserQuery) {

  log.Debug("login.go ::: entered function getUserFromAuthorities with authorities=%v", authorities)

  var arrayAuthorities []interface {} = authorities.([]interface {})

  for _, authRole := range arrayAuthorities {

    var authRoleString string = authRole.(string)

    log.Debug("login.go ::: starting finding authority=%v", authRoleString)

    foundUser, userQuery := getUserByAuthority ( authRoleString )

    if foundUser {
      query := getSignedInUserQueryForProxyAuth( userQuery.Result.Id )

      log.Debug("login.go ::: finished finding authority=%v returned=%v", authRoleString, query)

      if err := bus.Dispatch(query); err == nil {

        log.Debug("login.go ::: finished method USER FOUND for authority=%v returning query=%v", authRoleString, query)

        return true, query
      }
    }
  }

  log.Debug("login.go ::: finished method NO USER FOUND with authorities=%v", authorities)

  return false, nil
}

func getUserByAuthority( val string ) (bool, *m.GetUserByLoginQueryNew) {

  userQuery := m.GetUserByLoginQueryNew{Login: val}

  if err := bus.Dispatch(&userQuery); err == nil {
    log.Debug("login.go ::: getUserByAuthority finished finding bool=%v userQuery=%v", true, &userQuery)
    return true, &userQuery
  }

  log.Debug("login.go ::: getUserByAuthority finished finding bool=%v userQuery=%v", false, &userQuery)
  return false, &userQuery
}

func getSignedInUserQueryForProxyAuth( userId  int64) *m.GetSignedInUserQuery {

  query := m.GetSignedInUserQuery{}

  query.UserId = userId

  return &query
}

func lookupCallback(token map[string]interface{}, publickey string) (interface{}, error) {

  log.Debug("login.go ::: entered myLookupKey for token %v", token)

  log.Debug("login.go ::: client_id=%v, jti=%v, scope=%v, exp=%v, user_name=%v, authorities=%v, public key=%v",

    token["client_id"],token["jti"],token["scope"],token["exp"],token["user_name"],token["authorities"], setting.AuthProxyPublicKey)

  return []byte( publickey ), nil
}

func getTime() time.Time {

  if ( setting.TimestampOffset == 0 ) {
    return time.Now()
  }

  var returnTime time.Time = time.Now().Add( time.Duration( setting.TimestampOffset )*time.Hour*-1 )

  log.Debug("login.go ::: returning new date = %v", returnTime)

  return returnTime
}

func isValidToken(inputToken string, publickey string) (bool, string, interface{}) {

  if len(inputToken) == 0 {
    log.Debug("login.go ::: nil input token found")
    return false, "", nil
  }

  jwt.TimeFunc = getTime

  token, err := jwt.Parse(inputToken, func(token *jwt.Token) (interface{}, error) {

    if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
      return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
    }

    log.Debug("login.go ::: callback for token %v", token)

    return lookupCallback(token.Claims, publickey)
  })

  if token == nil {
    log.Debug("login.go ::: no token found ")
    return false, "", nil
  }

  log.Debug("login.go ::: returned token from validation token=%v errors=%v", token, err)

  if token.Valid {
    log.Debug("login.go ::: Token Validation Success!")

    user_name   := token.Claims["user_name"].(string)
    authorities := token.Claims["authorities"]

    return true, user_name, authorities
  } else if ve, ok := err.(*jwt.ValidationError); ok {
    if ve.Errors&jwt.ValidationErrorMalformed != 0 {
      log.Debug("login.go ::: Cannot recognize the token")
      return false, "", nil
    } else if ve.Errors&(jwt.ValidationErrorExpired |jwt.ValidationErrorNotValidYet) != 0 {
      log.Debug("login.go ::: Token Expired or not active yet")
      return false, "", nil
    } else {
      log.Debug("login.go ::: Couldn't handle token - Validation Error")
      return false, "", nil
    }
  } else {
    log.Debug("login.go ::: Couldn't handle token")
    return false, "", nil
  }
}
