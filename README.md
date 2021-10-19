# Nextensio Agent / Connector 

The agent specific code is in nxt_agent.js and connector specific code is in nxt_connector.js
Agent and connector does very similar kind of work and so you will find the code flow to be 
quite similar. The basic theory of operation of this code is as follows

## Building connector with version tag
By default, the version tag is set to "Development".

Syntax for building connector image with git's latest version tag:

From agent/go/connector directory run:

CGO_ENABLED=0 go build -tags netgo -a -v -ldflags="-X 'main.Version=`git tag -l "ALP*" | sort -r | head  -n 1`'"

For building docker container with version tags:

In Dockerfile.Build file, change the "Development" in main.Version=Development  to the version 
tag that you want to build with.

## Usage

### Basic Agent operation

1. User launches agent on the user device (laptop) using nodejs 
2. The agent code opens a port 8180 and listens on that, if someone connects to that port 
   from their browser (http://localhost:8180), the public/login.html page is served which
   prompts the user to login and authenticate themselves. 
3. Once authenticated, the agent code uses the information obtained from authentication 
   to connect to a nextensio cluster using websocket
4. The agent also opens a port 8181 which is a "web proxy" port - in your browser, you can
   open the broswer settings and ask the browser to forward any web browsing activity to 
   http://localhost:8181
5. When you browse a website, the browser forwards that request to port 8181 of the agent,
   agent gets that and sends it to nextensio cluster websocket. Agent takes the response
   from websocket and sends it back to the browser thats connected to agent's port 8181

### Basic Connector operation

1. Data center administrator launches connector on a data center server using nodejs
2. The connector code opens post 8180 - used for authenticating the connector the same
   way as we described above for the agent
3. The connector code also opens port 8081 which is used as part of the authentication
   process, explained later
4. Once the connector is authenticated it gets information like the connector name etc..
   and connects to a nextensio cluster. Note that the nextensio cluster to connect to
   is decided as a command line parameter to the connector - the authentication is not
   going to tell connector which gateway to connect to, that the connector will decide

### Launching agent

First install nodejs - plenty of docs on the web. After that in the agent code base, first 
say "npm install" - if it shows errors fix it , it will also tell you how to fix it. Next
say "npm run agent11" as an example - the options to give after "npm run" all comes from
package.json, there you also see the complete command line. 

The "npm run agent11" basically starts the agent saying that "I am agent with name agent-11".
Right now the name agent-11 is hard coded on the command line, it should get substituted 
with a name that comes after authentication with the controller. The controller will give an
agent name that is a combination of tenant-name+username - maybe tenant-name:username. The
Istio ingress gateway looks at the agent-name inserted in the X-nextensio headers to figure
out what istio namespace to use and pod to send the packet to etc..

The catchall parameter is kind of a hack at the moment for sending traffic that doesnt match
any specific route, read the code and search for catchall to know more

After the agent is launched, go to http://localhost:8180 on your browser and authenticate
yourself. The authentication details are in a section later. After that in your browser 
settings configure the proxy to point to localhost:8181 and assuming the connector has already
been launched and the nextensio gateways are all setup, your traffic will start flowing 
through nextensio agent--gateway--connector at the point.

Optionally if you dont want all your browser activity to go via agent, there is a proxy.pac
file which can be set in the browser to redirect only select websites to the proxy. Will need 
some googling to figure out how to add pac files to browser

### Launching connector

The steps are quite similar to launching agent as explained above, for example use "npm run conn11"

Note that usually we launch a connector on some cloud server like an aws server. So authenticating
the connector via http://localhost:8180 becomes a problem, not sure what the long term approach is,
maybe some text based authentication mechanism needs to be in place. But for now the only way is to
run a vncserver on the aws server and vnc to it from your laptop and launch a browser and authenticate
the same way as you authenticate the agent. And of course the login/password  for agent and connector
are different, again explained in the authentication section.

## Authentication/Onboarding

Basic summary of the process is as below:

The Agent AND Connector both has to authenticate themselves by logging into an SSO portal using 
their username/password credentials and then present the proof of authentication to the nextensio
controller. On seeing the proof of authentication, nextensio will provide further informatoin to
the agent/connector which will be used by agent/connector while connecting to the nextensio cluster

The IDP (Identity Provider) that authenticates the agent/connector can be any of the cloud based
IDPs like Okta or Azure or Google etc.., currently in this version of the code it is Okta

### Detailed steps

The below is how the exact steps happen, its the same set of steps for agent and connector. This
set of steps is referred to as "Authorization Code Flow" in Oauth2.0 documentation. For more indepth
understanding of the sequence, google for Authorization Code Flow and there will be plenty of docs
Also within Authorization Code flow there is something called PKCE mode, which is what we use here.

1. Agent/Connector serves a login page on port 8180 - the user can open a browser and point to
   http://localhost:8180 to login. Note that this need not be how the login is done, android/ios
   apps can provide a login page within the app itself without using a browser

2. When the username / password is entered, it is sent to the IDP (Okta), along with some more
   information identifying what app it is (client_id) and once the authentication is done, where
   the browser should send the authentication result (redirect_url)

   NOTE: Right now in the code we hard code Okta domain name, I am not sure how to make it "generic"
   so that tomorrow if we want to switch to Azure, how do we do that without an agent upgrade ?
   Is it enough that we use a generic domain name like authenticate.nextensio.net which is mapped 
   to Okta ? Thats possible, but there are different quirks specific to each IDP, so I am not sure
   whether we can ever change IDP without agent code change / agent upgrade

3. Okta verifies the username password and sends results back to the browser with something called
   "authorization code". The authorization code in one sentence is proof that the user has been 
   authenticated by Okta. The "sent back to the browser" is where the "redirect_url" comes into
   picture, Okta sends the result back to the browser and tells the browser "load the page 
   http://redirect_url/code=<authorization code>" .. Right now the redirect_url is set to the
   same as localhost:8180 the login page, and the login page has javascript code that parses the
   authorizaton code and does more stuff with it as below

4. The javascript code have added in the login page takes the authorization code and again goes 
   back to Okta and says "give me access token and id token" - in one line, the access token and
   id token encodes detailed information about the user, like the email id, the company/tenant
   name etc.. etc..

5. Once the javascript gets the access/id token, it needs to pass it onto the agent code running
   inside nodejs - note that the javascript running in the login page is running in the browser,
   and that is not "sharing" anything with the javascript running inside nodejs - nodejs just
   "served" the login page to the browser and after that both are seperate entities. So from the
   javascript in browser, we pass the access/id token to nodejs agent code by calling into port 8081

6. The agent code gets the access/id token and sends it to the controller and says "hey controller,
   you can use these tokens to know who I am, and once you are satisfied with my identity, please
   send me more information about myself".

7. The controller uses the access/id token to figure out who the user behind the agent is or who the
   connector is. The controller can decode the tokens and figure it out, but today the controller 
   contacts Okta again and presents the tokens to a "/user" endpoint and okta decodes the token 
   and gives controller the info. This will change in future, the controller will just decode it
   itself. And once the controller knows who the user is, it looks up the controllers mongodb 
   database and sends the below information

   username (email id), tenant (a uuid generated by mongodb for each tenant), nextensio gateway

   Agent connects to the nextensio gateway got from the result, and fills in the username in the
   uid field in x-nextensio-uuid field. Today the x-nextensio-connect just fills in the agent/connector
   name supplied on command line, but later we will change it to be a combination of tenant+username.

   Connector also does the same as agent, except connector doesnt use the gateway returned, it knows
   what gateway it has to connect to

Thats about it. The browser caches the login information, so when the agent is restarted, the login
page presented will say that the user is already logged in. We need to use the cached tokens in 
that case, but that is not coded up, so today we have to logout and login again if the agent or
connector is restarted

### Okta information

The Okta developer account used in the code base is https://dev-635657-admin.okta.com/admin/
The user name to login is apogphone@gmail.com and password is Nextensio238

Once you login to Okta, under the users section you can see users demoagent-1@nextensio.net and 
connector-1@nextensio.net, their passwords are both LetMeIn123   - so you can use that username
password to authenticate an agent / connector respectively. Or feel free to add/delete other users

## Settings done inside Okta

Inside Okta, we have created two "Applications" - both set as "SPA" (Single Page Application).
One application is for all agent/connector logins and they all have localhost:blah as their
redirect_uris - because the agent/connectors all login to a "local" website on the device 
whereas people logging into the controller/UX login to a global controller website. This is
in flux and we might change the way the agents login to the IDP/Okta (TODO)

1. Adding users - of course we need users added to authenticate agent/connectors
2. Under API->Trusted Origin, added http://localhost:8180 to make sure that the redirect_uri 
   is a trusted link
3. Under Applications, added a NextensioAgent app (used by agent and connector), clicking on that
   will provide the "client_id" info used in the code while contacting Okta. Inside the client,
   there will be boxes to configure login/logout redirect URLS, add http://localhost:8180 there
4. Under API->Authorization Servers, click edit on the one and only default authrization server, 
   and go to claims section and add a new claim called "tenant" and set the value to 
   user.organization and set it as included in any scope. This basically ensures that when the code
   asks for "more information" about the user (read about scopes and claims), the user.organization
   is also returned (its not returned by defualt)
5. For each user, click on edit and in the Organization field, enter the "Tenant ID" information -
   basically in the nextensio controller database (http://server.nextensio.net), we need to add
   corresponding users for each user in Okta. And each user in nextensio is added under some tenant,
   and when we login to server.nextensio.net and click on a tenant, it will display the Tenant ID.
   We pick that information and set it in the Organization field in Okta so that it gets sent down
   to the agent as part of access/id tokens. This is how we tie an Okta user to a Nextensio tenant

   NOTE: We have overloaded the organization field for this purpose, we can add a custom field of
   our own later if required
6. In the API-->Trusted origins section, add http://localhost:8180 with CORS and Redirect both ON

All the above info is specific to Okta obviously, Azure will do it some other way which we will
have to figure out
 
