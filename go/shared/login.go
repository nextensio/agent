package shared

// TODO: This is a hack to avoid having to figure out a way in android/ios to
// package an "asset" and read it as a file - infact in android an asset need
// not even be a file, its a zipped content inside the app package (apk) and
// we just get an android "Filestream" handle to it, which obviously we cant
// interpret from inside golang. The right thing to do here is to move the
// login page download to the controller itself - but then it becomes more
// complicated because Okta ends up asking us to punch in the controller URL
// for allowing cross-origin requests. And as of now we can have different
// controller URLs for testing (like 172.x) and we cant punch all of that in
// the okta account. So this needs some figuring out
var loginHtml = `<!doctype html>
<html lang="en">

<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, shrink-to-fit=no">
    <<link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.0/css/bootstrap.min.css"
        integrity="sha384-9aIt2nRpC12Uk9gS9baDl411NQApFmC26EwAOH8WgZl5MYYxFfc+NcPb1dKGj7Sk" crossorigin="anonymous">
        <title>Nextensio Networks!</title>
        <style>
            h1 {
                margin: 2em 0;
            }
        </style>
        <!-- widget stuff here -->
        <script src="https://global.oktacdn.com/okta-signin-widget/4.3.2/js/okta-sign-in.min.js"
            type="text/javascript"></script>
        <link href="https://global.oktacdn.com/okta-signin-widget/4.3.2/css/okta-sign-in.min.css" type="text/css"
            rel="stylesheet" />
</head>

<body>
    <div class="container">
        <h1 class="text-center">Nextensio Networks!</h1>
        <div id="messageBox" class="jumbotron">
            You are not logged in.
        </div>
        <!-- where the sign-in form will be displayed -->
        <div id="okta-login-container"></div>
        <button id="logout" class="button" onclick="logout()" style="display: none">Logout</button>
    </div>
    <script type="text/javascript">
        var oktaSignIn = new OktaSignIn({
            baseUrl: 'https://dev-635657.okta.com',
            redirectUri: 'http://localhost:8180/',
            clientId: '0oa24hr70oNBZW0b64x7',
            authParams: {
                pkce: true,
                responseMode: 'query',
                scopes: ['openid', 'email', 'profile']
            }
        });

        if (oktaSignIn.hasTokensInUrl()) {
            oktaSignIn.authClient.token.parseFromUrl().then(
                // If we get here, the user just logged in.
                function success(res) {
                    var accessToken = res.tokens.accessToken;
                    var idToken = res.tokens.idToken;

                    oktaSignIn.authClient.tokenManager.add('accessToken', accessToken);
                    oktaSignIn.authClient.tokenManager.add('idToken', idToken);

                    document.getElementById("messageBox").innerHTML = "Hello, " + idToken.claims.email + "! You just logged in! :)";
                    document.getElementById("logout").style.display = 'block';

                    var xmlHttp = new XMLHttpRequest();
                    var theUrl = 'http://localhost:8081/accessid/?access=' + accessToken.accessToken + '&id=' + idToken.idToken;
                    xmlHttp.open("GET", theUrl, false);
                    xmlHttp.send(null);
                },
                function error(err) {
                    console.log(err);
                }
            );
        } else {
            oktaSignIn.authClient.token.getUserInfo().then(function (user) {
                document.getElementById("messageBox").innerHTML = "Hello, " + user.email + "! You are *still* logged in! :)";
                document.getElementById("logout").style.display = 'block';
            }, function (error) {
                oktaSignIn.renderEl(
                    { el: '#okta-login-container' },
                    function success(res) { },
                    function error(err) {
                        console.log(err);
                    }
                );
            });
        }

        function logout() {
            oktaSignIn.authClient.signOut();
            location.reload();
        }
    </script>
</body>

</html>`
