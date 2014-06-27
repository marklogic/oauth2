xdmp:set-response-content-type("text/html"),
let $username := xdmp:get-current-user()
let $isLoggedIn := $username != "oauth-anon"
let $userDetails := /user[@name = $username]/provider-data
let $picture :=$userDetails/picture/text()

return
<html>
    <head>
        <style>
            <![CDATA[
            a { text-decoration:none; color:#C00831; }
            body { margin:auto; width:350px; padding:20px; }
            #login-action { text-align:center; font-size:36px; font-family:Helvetica; font-weight:bold; }
            #login-action span { font-size:14px; }
            #profile { background-color:#EFEFEF; height:50px; padding:5px; margin:10px; }
            #profile img { float:left; height:50px;}
            #profile div { float:left;padding: 14px 0 0 10px; }
            #profile span { font-size:0.8em; color:gray;}
            ]]>
        </style>
    </head>
<body>
<div id="login-action">
    {
        if( $isLoggedIn ) then
            element a { attribute href { "/logout.xqy" }, "Logout" }
        else
            element div {
                element span { "Log in with "},
                element br {},
                element a { attribute href { "/oauth2-facebook.xqy" }, "Facebook" },
                element br {},
                element span { " or "},
                element br {},
                element a { attribute href { "/oauth2-github.xqy" }, "Github" },
                element br {},
                element span { " or "},
                element br {},
                element a { attribute href { "/oauth2-google.xqy" }, "Google+" }
            }
    }
</div>

{
    if($isLoggedIn) then
        <div id="profile">
            <img src="{$picture}" />
            <div>
                <a href="{$userDetails/link/text()}">{$userDetails/name/text()}</a><br/>
                <span>via {xs:string( $userDetails/@name )}</span>
            </div>
        </div>
    else ()
}
</body>
</html>