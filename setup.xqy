xquery version "1.0-ml";
import module namespace oauth-user = "oauth2" at "/lib/oauth2.xqy";
import module namespace security-util = "security-util" at "/lib/security-util.xqy";

let $_ := security-util:createRole("oauth-anon", "Anonymous user role for oauth example")
let $_ := security-util:createRole("oauth-user", "Anonymous user role for oauth example")
let $_ := security-util:createRole("oauth-admin", "Admin user role for oauth example")

let $addRoles := security-util:addPrivileges("oauth-anon", 
    ("http://marklogic.com/xdmp/privileges/xdmp-invoke",
     "http://marklogic.com/xdmp/privileges/xdmp-eval",
     "http://marklogic.com/xdmp/privileges/xdmp-login",
     "http://marklogic.com/xdmp/privileges/xdmp-eval-in",
     "http://marklogic.com/xdmp/privileges/create-user",
     "http://marklogic.com/xdmp/privileges/any-uri",     
     "http://marklogic.com/xdmp/privileges/any-collection",
     "http://marklogic.com/xdmp/privileges/grant-all-roles",
     "http://marklogic.com/xdmp/privileges/get-user-names",
     "http://marklogic.com/xdmp/privileges/xdmp-value"))           
return (
    xdmp:eval(
    "xquery version '1.0-ml'; 
    import module namespace sec='http://marklogic.com/xdmp/security' at '/MarkLogic/security.xqy';
    sec:create-user('oauth-anon', 'OAuth2 Anonymous User', 'password', 'oauth-anon', (), ())", (),
    <options xmlns="xdmp:eval"><database>{xdmp:database("Security")}</database> </options>)     
  , xdmp:eval(
    "xquery version '1.0-ml'; 
    import module namespace sec='http://marklogic.com/xdmp/security' at '/MarkLogic/security.xqy';
    sec:create-user('oauth-admin', 'OAuth2 Admin User', 'password', 'oauth-admin', (), ())", (),
    <options xmlns="xdmp:eval"><database>{xdmp:database("Security")}</database> </options>)
  ),
let $_ := security-util:addRoleToRole("oauth-user", "oauth-anon")
let $_ := security-util:addRoleToRole("oauth-admin", "oauth-user")

let $_ := xdmp:document-insert("/config/oauth-config.xml",
    <oauth_config>
        <provider name="facebook">
            <id>127879060598755</id>
            <secret>de00736b30d270bacd62f35e5e5f46de</secret>
            <access_token_url>https://graph.facebook.com/oauth/access_token</access_token_url>
            <authorize_url>https://graph.facebook.com/oauth/authorize</authorize_url>
            <redirect_url>http://localhost:8020/oauth2-facebook.xqy</redirect_url>
        </provider>
        <provider name="github">
            <id>27e9df63403f85eaa388</id>
            <secret>dcae4c44187bd63bd7e316c9e62d7a1ab1d96bb0</secret>
            <access_token_url>https://github.com/login/oauth/access_token</access_token_url>
            <authorize_url>https://github.com/login/oauth/authorize</authorize_url>
            <redirect_url>http://localhost:8020/oauth2-github.xqy</redirect_url>
        </provider>
    </oauth_config>,
        (xdmp:permission("oauth-anon", "read"), xdmp:permission("oauth-admin", "update"))
)
return ()