xquery version "1.0-ml";
import module namespace oauth2 = "oauth2" at "/lib/oauth2.xqy";
declare namespace xdmphttp="xdmp:http";

let $code           := xdmp:get-request-field("code")
let $provider       := xdmp:get-request-field("provider")
let $auth_provider  := /oauth_config/provider[@name eq $provider]
let $client_id      := $auth_provider/id/text()
let $client_secret  := $auth_provider/secret/text()
let $redirect_url   := $auth_provider/redirect_url/text()
let $scope          := if($provider = "github") then "&amp;scope=user" else ""

let $authorization_url := fn:concat($auth_provider/authorize_url/text(),
                                    "?client_id=", $client_id, 
                                    "&amp;redirect_uri=", xdmp:url-encode($redirect_url))
                                     
let $access_token_url := fn:concat($auth_provider/access_token_url/text(),
                                   "?client_id=",$client_id, 
                                   "&amp;redirect_uri=", xdmp:url-encode($redirect_url),
                                   "&amp;code=", $code,
                                   "&amp;client_secret=", $client_secret,
                                   $scope)
                         
return
    if(not($code)) then
        xdmp:redirect-response($authorization_url)
    else 
        let $access_token_response := xdmp:http-get($access_token_url,
          <options xmlns='xdmp:http-get'><format xmlns='xdmp:document-get'>text</format></options>)
        return
            if($access_token_response[1]/xdmphttp:code/text() eq "200") then
                let $oauth_token_data := oauth2:parseAccessToken($access_token_response[2])
                let $provider_user_data := oauth2:getUserProfileInfo($provider, $oauth_token_data)
                return 
                    if($provider_user_data) then
                        let $user_id := $provider_user_data/id/text()                       
                        let $markLogicUsername := oauth2:getOrCreateUserByProvider($provider, $user_id, $provider_user_data) 
                        let $authResult := oauth2:loginAsMarkLogicUser($markLogicUsername)
                        let $referer := xdmp:get-request-header("Referer")
                        return 

                            (: the referrer gets lost sometimes from the original site, namely when you need to login iwth your credential
                               at facebook. If you're already logged in then it works fine. So if the referer is from facebook just
                               redirected to the root :)
                            if($referer and fn:not(fn:starts-with($referer, "http://www.facebook.com"))) then
                                xdmp:redirect-response($referer)
                            else
                                xdmp:redirect-response("/")
                    else
                        "Could not get user information"
            else
                (: if there's a problem just pass along the error :)
                xdmp:set-response-code($access_token_response[1]/xdmphttp:code/text(),
                                       $access_token_response[1]/xdmphttp:message/text())
