# Mapping ip address to names

A major power of nextension solution comes from the ability to map packets/payload 
to service names. For example a packet/payload to netflix.com will be tagged as 
nexflix.com and that allows us to apply powerful policies in the nextensio cluster

This document discusses how we can derive the service name from the packet/payload

## HTTP Proxy mode

This is the easiest way to get a "name" from an application. Applications (like browsers)
are built with the ability to redirect their HTTP requests to proxies, and these redirects
are done before any DNS lookup / ip addresses etc.. come into picture. So if nextensio
agent runs in proxy mode, for all the applications that are proxy aware, we can easily 
get the service name

### Clientless proxy 

Another technique some people employ for running an agent/proxy inside the browser itself
is by intercepting the browser's AJAX layer itself. Bitglass calls this "AJAX-VM" -
https://www.bitglass.com/agentless-mobile-security - the browser is not doing any proxy
redirect, rather the browser's XHttpRequest() api that makes the http call is intercepted
and then the agent code is inserted inside. Again here getting the name is easy

## Naive app: L4 / L3 mode

Native app, ie apps that are not browser based, might not play well with proxies, they
might not be programmed with proxy capability, so we need the nextensio agent to intercept
their data at the networking layer of the device (phone/laptop)

In L4 mode the agent terminates tcp/udp and carries the payload via nextensio software.
In L3 mode the unterminated IP packets are carried through nextensio software. In either
case, what the agent sees is an IP packet with  destination ip/port etc.. How do we get
a service name from that ?? Lets look at the possible options

### Asking customer to punch in ip addresses in our controller/portal

For example, lets say customer is using salesforce app, it is cloud hosted salesforce,
but they have configured it such that salesforce allows only nextensio cluster ip addresses
to access it - so its like a public cloud application that has restricted access. And this
is common for many applications like office365 which can also be restriced to access from
an enterprise IP address range only.

Now if we use the nextensio agent to allow the salesforce native app (or office365) to access
their public cloud hosting this enterprise's salesforce account, this will mean that all we
see is some salesforce ip addresses. Now if we have a nextensio policy that says something
like "only users in finance department can access salesforce", we are at a loss here because
we dont know from the ip whether its salesforce

We can always ask the enterprise IT admin to go to the nextensio portal and configure the 
ip addresses corresponding to the salesforce service. But most often the IT admin has no clue
and will end up asking salesforce. And salesforce themselves often have no clue because their
IP addresses keep changing/adding/deleting - and the model that they usually do (seen at microsoft)
is that they publish a list of ip addresses once in a month or so in a word doc and send it 
across to whoever wants it. So this is already a mechanism many sd-wan vendors use to identify
salesforce and apply higher level policies based on salesforce as a "name". 

So if nextensio also has to resort to this technique, we will become a LAUGHING STOCK and 
immediately we will be ridiculed for resorting to unrelible mechanisms for something thats 
core / fundamental to our solution - so this option WILL NOT FLY

### Routing using the application name

This is actually a pretty good option - we dont really care about the granularity of what servers
a salesforce app is accessing and what is the fqdns for each of them. Any packet that comes out
of a salesforce app is assumed to fall into a broad bucket called "salesforce" - so even if the
salesforce app tries to access say adwords.google.com for advertising, even that will get classified
as "salesforce" - that should be allright. So now the question becomes how do we get the application
name that generates the packet ?

#### IOS

IOS has two modes for a vpn agent. 

1. A full proxy mode where the applicaton's terminated tcp/udp is given to the vpn agent
   https://developer.apple.com/documentation/networkextension/app_proxy_provider

2. A packet mode where the applicatoins l3 packets are given, but the source app generating
   the packets can be identified (see source-application mode in the below link)
   https://developer.apple.com/documentation/networkextension/packet_tunnel_provider

The IOS documentation is not very clear, 1) above is possible only in the MDM mode, 
2) above looks like is also possible only in MDM mode, but not clear.

Asking users to put their personal phones in MDM mode will be totally unacceptable, so this
option wont fly either

#### Android

Android seems to have no standard way of doing this either, although people are suggesting
various tricks to do that like below - its at least feasible on android because every 
applicatoin on android is given a unique userid and hence given a socket's source port,
at least the kernel has the informatoin about the app that opened that socket

https://android.stackexchange.com/questions/203868/how-to-view-network-traffic-requested-by-a-specific-app

#### Linux

Linux keeps no track of which "application" opened a socket, we can get the process id 
given a socket source port, but process id wont really help in getting to an application

#### MacOS/Windows 

No idea if the app can be identified from socket .. Need digging ????

So given that there is really no standard way of associating a packet to an application,
this technique can also be ruled out.

### Configuring a dns server for the agent VPN connection

Having DNS servers for VPN clients is not a new thing. For applications using traditional
VPN, they will be accessing private domain names and to resolve that, all vpn mechanisms
in android/ios/windows provides a way to set a dns server for the vpn.

So nextensio can also provide a dns server to ios/android when we launch our agent. The
dns server can be just any ip address that we cook up, and inside the nextensio cluster
we can run a small service that just provides some random ip addresses for each name,
nextensio does not care about ip addresses, the addresses are just to keep the device's
networking stack happy.

So even for public domains like salesforce.com or office365.com, we will end up faking
some ip address. And once the packet reaches the nextensio cluster, we can find out the
service name by mapping back from IP to the name. We can infact use consul to do the
same - we can add an entry in consul for salesforce.com with ip address say 10.0.0.1 and
we can lookup consul for 10.0.0.1 and get back salesforce.com

This seems to be the only really "clean" option available to solve the problem, for 
one more reason. Tomorrow lets say nextensio decides to sell a small device running our
agent, for those customers who dont want agent on phones, we need to ensure the solution
works without architectural modifications in that case. So as long as we rely on the
dns server approach, the custom hardware we provide will basically advertise the dns
server in its dhcp response - and everything should continue working as usual whether
its agent on phone or phone connecting to a nextensio hardware running the agent.

#### Problems with the dns server approach

1. DNS over tls / DNS over HTTPS is starting to be the defacto standard - android9 
   introduces a setting by which people can turn on "secure dns" - and the standard
   google dns servers like dns.google.com and coudflare servers like 1.1.1.1 all 
   support dns over tls. But the problem is that the android vpnService APIs seem 
   to be lagging behind / not updated to handle secure dns. So if someone turns on
   secure dns in their phone, and provide a standard dns server IP in their 
   vpnService API calls, looks like android is not happy with that - because
   android says "hey, you have turned on secure dns in the system config, but your
   vpnService is providing the IP on an in-secure dns server, so I wont send any
   dns requests" ! See the link below for detailed discussions on this problem

   https://github.com/tailscale/tailscale/issues/915

   This looks like just a case of android team not updating their APIs to match 
   the new features. So what the android team should do according to the tailscale
   team is either 

   a) Provide an option in the vpnService apis to give the IP of a secure dns server

   OR 

   b) Understand that a VPN by nature is supposed to be "secure" and hence its is 
      ALLRIGHT to have an in-secure DNS server IP configured for a VPN. Because 
      the dns requests over the vpn are gonna be encrypted anyways

   I really really hope android fixes the issue using approach b) becuase approach
   number a) will require us to implement a proper dns server with tls negotiation
   and certificates etc.., which will be an unnecessary overkill for us


   So for now, what the tailscale team recommends is to get the android users to 
   turn OFF the default secure dns config on their phones. I hope the android 
   team fixes this soon or else it will get ugly where we have to help users 
   manually do this stuff

2. The documentation on the behaviour of dns server installed by VPN clients is
   not very clear. Like will android/ios cache the dns response in the same 
   global dns cache or there will be a seperate cache for the VPN client ?
   If its a global cache, then we might mess things up - because we are going
   to provide random ip addresses for say adwords.google.com if an app goes
   via nextensio. Now if the user stops the nextensio agent, the next set
   of accesses to adwords.google.com will time out till TTL expiry. To solve
   this we have the below options

   a) As much as possible give out proper IP addresses, ie adwords.google.com
      will be looked up by the nextensio dns server and we will respond with
      a proper IP

   b) Give out ranom ip addresses, but with a TTL of say 1 second. But this 
      will increase the load on the cluster with a flood of dns requests
 
   c) Give out random ip addresses, if the agent is stopped, flush the dns
      cache of the system. This might also be frowned upon by the other 
      applications on the system

   Option a) seems to be the right thing to do. So on the cluster we have to
   do a proper dns resolution and give a proper IP back and then remember the
   mapping. And we also need to age out the dns entry based on ttl. So we are
   actually asking for a full fledged dns server in the cluster, just having
   a quick-and-dirty-store-in-consul might not work
