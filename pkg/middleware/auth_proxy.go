package middleware

import (
  "github.com/grafana/grafana/pkg/bus"
  "github.com/grafana/grafana/pkg/log"
  m "github.com/grafana/grafana/pkg/models"
  "github.com/dgrijalva/jwt-go"
  "github.com/grafana/grafana/pkg/setting"
  "errors"
  "time"
  "fmt"
)

func initContextWithAuthProxy(ctx *Context) bool {

  log.Debug("auth_proxy.go ::: entered method")

  if !setting.AuthProxyEnabled {
    log.Info("auth_proxy.go ::: returning false")
    return false
  }

  proxyHeaderValue := ctx.Req.Header.Get(setting.AuthProxyHeaderName)

  log.Debug("auth_proxy.go ::: reading proxyHeaderValue returning %v", proxyHeaderValue)

  if len(proxyHeaderValue) == 0 {
    log.Info("auth_proxy.go ::: proxyHeaderValue returned null")
    //TODO: Redirect or Access is denied
    return false
  }

  valid, username, authorities := isValidToken(proxyHeaderValue)

  if ( !valid ) {
    log.Debug("auth_proxy.go ::: isValidToken returning %v", valid)

    ctx.Handle(401, "Access is denied", errors.New("Access is denied"))
    return false
  }

  log.Debug("auth_proxy.go ::: going to validate username %v and authorities %v", username, authorities)


  if authorities == nil {

    var errorMessage string = "Unknown authorities returned"
    var errorR       error  = errors.New( errorMessage )

    log.Error (500, errorMessage, errorR)

    ctx.Handle(500, errorMessage, errorR )

    return true

  }

  found, query := getUserFromAuthorities(authorities)

  log.Debug("auth_proxy.go ::: getUserFromAuthorities returning found=%v query=%v", found, query)

  if ( !found ) {

    var errorMessage string = "Failed find user specifed in auth proxy header"
    var errorR       error  = errors.New( errorMessage )

    log.Error (500, errorMessage, errorR)

    ctx.Handle(500, errorMessage, errorR )

    return true
  } else {
    log.Debug("auth_proxy.go ::: found user query=%v", query)
  }

  log.Debug("auth_proxy.go ::: before initialize session %v", username)

  // initialize session
  if err := ctx.Session.Start(ctx); err != nil {
    log.Error(3, "Failed to start session", err)
    return false
  }

  log.Debug("auth_proxy.go ::: after initialize session %v", username)

  query.Result.PsevdoUsername = username

  ctx.SignedInUser    = query.Result
  ctx.PsevdoUsername  = username
  ctx.IsSignedIn      = true
  ctx.Session.Set(SESS_KEY_USERID, ctx.UserId)

  return true
}

func getUserFromAuthorities( authorities interface{} ) (bool, *m.GetSignedInUserQuery) {

  log.Debug("auth_proxy.go ::: entered function getUserFromAuthorities with authorities=%v", authorities)

  var arrayAuthorities []interface {} = authorities.([]interface {})

  for _, authRole := range arrayAuthorities {

    var authRoleString string = authRole.(string)

    log.Debug("auth_proxy.go ::: starting finding authority=%v", authRoleString)

    foundUser, userQuery := getUserByAuthority ( authRoleString )

    if foundUser {
      query := getSignedInUserQueryForProxyAuth( userQuery.Result.Id )

      log.Debug("auth_proxy.go ::: finished finding authority=%v returned=%v", authRoleString, query)

      if err := bus.Dispatch(query); err == nil {

          log.Debug("auth_proxy.go ::: finished method USER FOUND for authority=%v returning query=%v", authRoleString, query)

          return true, query
      }
    }
  }

  log.Debug("auth_proxy.go ::: finished method NO USER FOUND with authorities=%v", authorities)

  return false, nil
}

func getUserByAuthority( val string ) (bool, *m.GetUserByLoginQueryNew) {

  userQuery := m.GetUserByLoginQueryNew{Login: val}

  if err := bus.Dispatch(&userQuery); err == nil {
    log.Debug("auth_proxy.go ::: getUserByAuthority finished finding bool=%v userQuery=%v", true, &userQuery)
    return true, &userQuery
  }

  log.Debug("auth_proxy.go ::: getUserByAuthority finished finding bool=%v userQuery=%v", false, &userQuery)
  return false, &userQuery
}

func getSignedInUserQueryForProxyAuth( userId  int64) *m.GetSignedInUserQuery {

  query := m.GetSignedInUserQuery{}

    query.UserId = userId

  return &query
}

func lookupCallback(token map[string]interface{}) (interface{}, error) {

  log.Debug("auth_proxy.go ::: entered myLookupKey for token %v", token)

  log.Debug("auth_proxy.go ::: client_id=%v, jti=%v, scope=%v, exp=%v, user_name=%v, authorities=%v, public key=%v",

    token["client_id"],token["jti"],token["scope"],token["exp"],token["user_name"],token["authorities"], setting.AuthProxyPublicKey)

  var public_key string = "-----BEGIN PUBLIC KEY-----\n" + setting.AuthProxyPublicKey + "\n-----END PUBLIC KEY-----"

  return []byte( public_key ), nil
}

func getTime() time.Time {

  if ( setting.TimestampOffset == 0 ) {
    return time.Now()
  }

  var returnTime time.Time = time.Now().Add( time.Duration( setting.TimestampOffset )*time.Hour*-1 )

  log.Debug("auth_proxy.go ::: returning new date = %v", returnTime)

  return returnTime
}

func isValidToken(inputToken string) (bool, string, interface{}) {

  if len(inputToken) == 0 {
    log.Debug("auth_proxy.go ::: nil input token found")
    return false, "", nil
  }

  jwt.TimeFunc = getTime

  token, err := jwt.Parse(inputToken, func(token *jwt.Token) (interface{}, error) {

    if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
      return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
    }

    log.Debug("auth_proxy.go ::: callback for token %v", token)

    return lookupCallback(token.Claims)
  })

  if token == nil {
    log.Debug("auth_proxy.go ::: no token found ")
    return false, "", nil
  }

  log.Debug("auth_proxy.go ::: returned token from validation token=%v errors=%v", token, err)

  if token.Valid {
    log.Debug("auth_proxy.go ::: Token Validation Success!")

    user_name   := token.Claims["user_name"].(string)
    authorities := token.Claims["authorities"]

    return true, user_name, authorities
  } else if ve, ok := err.(*jwt.ValidationError); ok {
    if ve.Errors&jwt.ValidationErrorMalformed != 0 {
      log.Debug("auth_proxy.go ::: Cannot recognize the token")
      return false, "", nil
    } else if ve.Errors&(jwt.ValidationErrorExpired |jwt.ValidationErrorNotValidYet) != 0 {
      log.Debug("auth_proxy.go ::: Token Expired or not active yet")
      return false, "", nil
    } else {
      log.Debug("auth_proxy.go ::: Couldn't handle token - Validation Error")
      return false, "", nil
    }
  } else {
    log.Debug("auth_proxy.go ::: Couldn't handle token")
    return false, "", nil
  }
}
