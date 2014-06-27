xquery version "1.0-ml";
import module namespace oauth2 = "oauth2" at "/lib/oauth2.xqy";
declare namespace xdmphttp="xdmp:http";

declare variable $code           := xdmp:get-request-field("code");
declare variable $provider       := "google";
declare variable $auth_provider  := /oauth_config/provider[@name eq $provider];
declare variable $client_id      := $auth_provider/id/text();
declare variable $client_secret  := $auth_provider/secret/text();
declare variable $redirect_url   := $auth_provider/redirect_url/text();
declare variable $api_key        := $auth_provider/api_key/text();

declare function local:request-auth()
{
  let $url := fn:concat($auth_provider/authorize_url/text(),
                        "?client_id=", $client_id,
                        "&amp;redirect_uri=", xdmp:url-encode($redirect_url),
                        "&amp;scope=https://www.googleapis.com/auth/plus.me",
                        "&amp;response_type=code")
  return
    xdmp:redirect-response($url)
};

declare function local:request-token()
{
  let $data := fn:concat("code=", $code, "&amp;",
                         "client_id=", $client_id, "&amp;",
                         "client_secret=", xdmp:url-encode($client_secret), "&amp;",
                         "redirect_uri=", xdmp:url-encode($redirect_url), "&amp;",
                         "grant_type=authorization_code")
  let $opts := <options xmlns='xdmp:http'>
                 <headers>
                   <content-type>application/x-www-form-urlencoded</content-type>
                 </headers>
                 <data>{$data}</data>
               </options>
  let $url := $auth_provider/access_token_url/text()
  let $x-url := "http://localhost/cgi-bin/echo.pl"
  let $response := xdmp:http-post($url, $opts)
  return
    if ($response[1]/xdmphttp:code = 200)
    then
      let $map := xdmp:from-json(xdmp:binary-decode($response[2], "utf-8"))
      let $access_token := map:get($map, "access_token")
      let $refresh_token := map:get($map, "refresh_token")
      let $trace := xdmp:log(concat("token: ", $access_token))
      return
        if ($access_token)
        then
          let $url := concat("https://www.googleapis.com/plus/v1/people/me?pp=1&amp;key=", $api_key)
          let $opts := <options xmlns='xdmp:http'>
                         <headers>
                           <authorization>OAuth {$access_token}</authorization>
                         </headers>
                       </options>
          let $response := xdmp:http-get($url, $opts)
          return
            if ($response[1]/xdmphttp:code = 200)
            then
              let $map := xdmp:from-json(xdmp:binary-decode($response[2], "utf-8"))
              let $data
                := <provider-data name="google">
                     <id>{map:get($map,"id")}</id>
                     <name>{map:get($map,"displayName")}</name>
                     <link>{map:get($map,"url")}</link>
                     <gender>{map:get($map,"gender")}</gender>
                     <picture>{map:get(map:get($map, "image"), "url")}</picture>
                   </provider-data>
              let $user_id := $data/id/text()
              let $markLogicUsername := oauth2:getOrCreateUserByProvider($provider, $user_id, $data)
              let $authResult := oauth2:loginAsMarkLogicUser($markLogicUsername)
              let $referer := xdmp:get-request-header("Referer")
              return
                (: the referrer gets lost sometimes from the original site, ... :)
                xdmp:redirect-response("/")
            else
              "Could not get user information"
        else
          "Could not get access token"
    else
      (: if there's a problem just pass along the error :)
      xdmp:set-response-code($response[1]/xdmphttp:code/text(),
                             $response[1]/xdmphttp:message/text())
};

let $trace := xdmp:log(concat("uri: ", xdmp:get-request-url()))
return
  if (empty($code))
  then
    local:request-auth()
  else
    local:request-token()

