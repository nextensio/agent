//
//  PacketTunnelProvider.swift
//  NextensioPacketTunnel
//
//  Created by Rudy Zulkarnain on 2/7/21.
//

import NetworkExtension
import os.log
import IPAddress_v4

let mtu = 1500;
var highmem = 0;

enum IPVersion: UInt8 {
    case IPv4 = 4, IPv6 = 6
}

enum PacketType: UInt8 {
    case TCP = 6, UDP = 17, ICMP = 1
}

// A enum describing NextensioAgentGoBridge log levels defined in `apis.go`.
public enum NextensioGoBridgeLogLevel: Int32 {
    case debug = 0
    case info = 1
    case error = 2
}

class PacketTunnelProvider: NEPacketTunnelProvider {
    var conf = [String: AnyObject]()
    var pendingStartCompletion: ((NSError?) -> Void)?
    var onboarded = false
    var force_onboard = false
    var keepalive = 30
    var last_version = ""
    var uuid = UUID().uuidString
    var stopKeepalive = false
    var domains = [String]()
    var subnets = [IPNetwork_v4]()
    var attractAll = false

    override init() {
        super.init()
    }
    
    private func onboardController(accessToken: String) {
        os_log("onboard Controller")
        
        //create the url with NSURL
        let url = URL(string: "https://server.nextensio.net:8080/api/v1/global/get/onboard")! 
        //create the session object
        let session = URLSession.shared
        //now create the URLRequest object using the url object
        var request = URLRequest(url: url)
        request.httpMethod = "GET"
        request.setValue("application/json", forHTTPHeaderField:"Content-Type")
        request.setValue("Bearer \(accessToken)", forHTTPHeaderField:"Authorization")
        request.timeoutInterval = 60.0

        //create dataTask using the session object to send data to the server
        let task = session.dataTask(with: request as URLRequest, completionHandler: { data, response, error in
            guard error == nil else {
                if #available(macOS 11.0, *) {
                    os_log("url error %{public}s", error!.localizedDescription)
                }
                self.pendingStartCompletion?(NSError(domain:"onboarding url failed", code:0, userInfo:nil))
                self.pendingStartCompletion = nil
                return
            }
            guard let data = data else {
                os_log("data error")
                self.pendingStartCompletion?(NSError(domain:"onboarding data failed", code:0, userInfo:nil))
                self.pendingStartCompletion = nil
                return 
            }
            do {
                //create json object from data
                if var onboard = try JSONSerialization.jsonObject(with: data, options: .mutableContainers) as? [String: Any] {
                    self.onboardNextensioAgent(accessToken: accessToken, json: onboard)
                    self.turnOnNextensioAgent()
                    self.pendingStartCompletion?(nil)
                    self.pendingStartCompletion = nil
                    os_log("Successfully onboarded")
                    return
                }
            } catch _ {
                os_log("error in json serialization")
                self.pendingStartCompletion?(NSError(domain:"onboarding json failed", code:0, userInfo:nil))
                self.pendingStartCompletion = nil
                return 
            }
        })
        task.resume()
        return
    }
    
    private func agentKeepalive(accessToken: String) {
        //create the url with NSURL
        let keepURL = String(format:"https://server.nextensio.net:8080/api/v1/global/get/keepalive/%@/%@", last_version, uuid)
        let url = URL(string: keepURL)!
        //create the session object
        let session = URLSession.shared
        session.configuration.httpMaximumConnectionsPerHost = 1;
        session.configuration.timeoutIntervalForRequest = 60;
        session.configuration.timeoutIntervalForResource = 60;
        //now create the URLRequest object using the url object
        var request = URLRequest(url: url)
        request.httpMethod = "GET"
        request.setValue("application/json", forHTTPHeaderField:"Content-Type")
        request.setValue("Bearer \(accessToken)", forHTTPHeaderField:"Authorization")
        request.timeoutInterval = 60.0

        //create dataTask using the session object to send data to the server
        let task = session.dataTask(with: request as URLRequest, completionHandler: { data, response, error in
            guard error == nil else {
                if #available(macOS 11.0, *) {
                    os_log("url error %{public}s", error!.localizedDescription)
                }
                return
            }
            guard let data = data else {
                os_log("keepalive: data error")
                return
            }
            do {
                //create json object from data
                if let keepalive = try JSONSerialization.jsonObject(with: data, options: .mutableContainers) as? [String: Any] {
                    if keepalive["version"] as! String != self.last_version {
                        self.force_onboard = true
                        os_log("keepalive version mismatch %{public}@, %{public}@", keepalive["version"] as! String, self.last_version)
                    }
                    os_log("keepalive: Successful")
                    return
                }
            } catch _ {
                os_log("keepalive: error in json serialization")
                return
            }
        })
        task.resume()
        return
    }
    
    private func setupVPN() {
        // the `tunnelRemoteAddress` is meaningless because we are not creating a tunnel.
        let networkSettings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: "127.0.0.1")
        
        // Refers to NEIPv4Settings#includedRoutes or NEIPv4Settings#excludedRoutes,
        // which can be used as basic whitelist/blacklist routing.
        
        let ipv4Settings = NEIPv4Settings(addresses: ["169.254.2.1"], subnetMasks: ["255.255.255.0"])

        // An informative/interesting rant on how mac DNS works is below:
        // https://threadreaderapp.com/thread/1380388035250941957.html
        if self.attractAll {
            // We want all default traffic to go via nextensio, so we need DNS
            // servers for that. TODO: We can let these dns server IPs be configured
            // via controller
            let dnsSettings = NEDNSSettings(servers: ["8.8.8.8", "8.8.4.4"])
            dnsSettings.matchDomains = [""] // match all
            networkSettings.dnsSettings = dnsSettings
            ipv4Settings.includedRoutes = [
                NEIPv4Route.default()
            ]
        } else {
            // Only our private domains need to be dns resolved by us,
            // the public domains can go to whatever dns server is configured
            // And for private domains, the dns server IP doesnt really matter,
            // we parse the dns requests and respond to it ourselves
            let dnsSettings = NEDNSSettings(servers: ["100.64.1.1"])
            dnsSettings.matchDomains = self.domains
            dnsSettings.matchDomainsNoSearch = true
            networkSettings.dnsSettings = dnsSettings
            // We advertise IP addresses in the CGNAT range for private services
            ipv4Settings.includedRoutes = [
                NEIPv4Route(destinationAddress: "100.64.0.0", subnetMask: "255.192.0.0"),
            ]
            for s in self.subnets {
                if s.networkAddress != nil && s.networkAddress?.address != nil && s.netMask != nil && s.netMask?.address != nil {
                    ipv4Settings.includedRoutes?.append(NEIPv4Route(destinationAddress: s.networkAddress!.address!, subnetMask: s.netMask!.address!))
                }
            }
        }
        
        ipv4Settings.excludedRoutes = [
        ]
        networkSettings.ipv4Settings = ipv4Settings
        networkSettings.mtu = mtu as NSNumber?
        
        if (conf["highMem"] as! Bool) == true {
            highmem = 1;
        }
        // Save the settings
        self.setTunnelNetworkSettings(networkSettings) { error in
            os_log("Network tunnel saved")
        }
    }


    @objc func runner(sender:Any) {
        let direct = sender as! String
        if #available(macOS 11.0, *) {
            os_log("agent_init %{public}lu", Thread.current)
        }
        Thread.setThreadPriority(1);
        agent_init(1 /*apple*/, direct == "true" ? 1 : 0,  UInt32(mtu), UInt32(highmem), 0)
    }

    private func refresh(refreshToken: String) {
        let rUrl =  "https://login.nextensio.net/oauth2/default/v1/token?client_id=0oav0q3hn65I4Zkmr5d6&redirect_uri=http://localhost:8180/&response_type=code&scope=openid%20offline_access&grant_type=refresh_token&refresh_token=" + refreshToken
        let url = URL(string: rUrl)!
        //create the session object
        let session = URLSession.shared
        session.configuration.httpMaximumConnectionsPerHost = 1;
        session.configuration.timeoutIntervalForRequest = 60;
        session.configuration.timeoutIntervalForResource = 60;
        //now create the URLRequest object using the url object
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField:"Accept")
        request.setValue("application/x-www-form-urlencoded", forHTTPHeaderField:"Content-Type")
        request.setValue("no-cache", forHTTPHeaderField:"cache-control")
        request.timeoutInterval = 60.0
        let empty = [String: String]()
        guard let httpBody = try? JSONSerialization.data(withJSONObject: empty, options: []) else {
            return
        }
        request.httpBody = httpBody
        
        //create dataTask using the session object to send data to the server
        let task = session.dataTask(with: request as URLRequest, completionHandler: { data, response, error in
            guard error == nil else {
                if #available(macOS 11.0, *) {
                    os_log("url error %{public}s", error!.localizedDescription)
                }
                return
            }
            guard let data = data else {
                os_log("refresh: data error")
                return
            }
            do {
                //create json object from data
                if let tokens = try JSONSerialization.jsonObject(with: data, options: .mutableContainers) as? [String: Any] {
                    self.conf["access"] = tokens["access_token"] as! NSString
                    self.conf["refresh"] = tokens["refresh_token"] as! NSString
                    os_log("refresh Success")
                    return
                }
            } catch _ {
                os_log("refresh: error in json serialization")
                return
            }
        })
        task.resume()
        return
        
    }
    
    @objc func doOnboard(sender: Any) {
        if #available(macOS 11.0, *) {
            os_log("doOnboard %{public}lu", Thread.current)
        }
        var last_keepalive = DispatchTime.now()
        var last_refresh = DispatchTime.now()
        while true {
            if stopKeepalive {
                return
            }
            if conf["access"] == nil {
                // Till user logs in we sleep for less time
                Thread.sleep(forTimeInterval: 1)
                continue
            }
            let now = DispatchTime.now()
            if onboarded {
                let nanoTime = now.uptimeNanoseconds - last_keepalive.uptimeNanoseconds
                let elapsed = Double(nanoTime) / 1_000_000_000
                if Int(elapsed) >= keepalive {
                    agentKeepalive(accessToken: (conf["access"] as! String))
                    last_keepalive = now
                }
            }
            let nanoTime = now.uptimeNanoseconds - last_refresh.uptimeNanoseconds
            let elapsed = Double(nanoTime) / 1_000_000_000
            // Okta tokens expire in one hour, start refreshing them 15 mins before expiry
            if elapsed >= 45*60 {
                refresh(refreshToken: conf["refresh"] as! String)
                last_refresh = now
            }
            if !onboarded || force_onboard {
                self.onboardController(accessToken: (conf["access"] as! String))
            }
            Thread.sleep(forTimeInterval:  3)
        }
    }
    
    func startAgent(direct: String) {
        let t = Thread(target: self, selector: #selector(runner(sender:)), object: direct)
        t.start()
    }

    override func startTunnel(options: [String : NSObject]?, completionHandler: @escaping (Error?) -> Void) {
        os_log("startTunnel using Network Extension configuration on mac")
        self.conf = (self.protocolConfiguration as! NETunnelProviderProtocol).providerConfiguration! as [String : AnyObject]

    // System extension runs in one single process, and it is given one of these objects
    // each time user asks for vpn on - so there is no way to save a 'state' in the object
    // which says we have already started a thread for nextensio data processing, hence having
    // to maintain that state in the thread itself which tells us if its already started or
    // not. The other option is pbbly we can try to kill the thread if this object gets a
    // tunnel stop request. But that gets more complicated (I think)
	let started = agent_started()
        // start agent
        if started == 0 {
            os_log("Agent starting")
            self.startAgent(direct: "false")
        } else {
            os_log("Agent started previously")
        }
        let t = Thread(target: self, selector: #selector(doOnboard(sender:)), object: nil)
        t.start()
        self.pendingStartCompletion = completionHandler
        self.setupVPN()
    }

    override func stopTunnel(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        self.stopKeepalive = true
        super.stopTunnel(with: reason, completionHandler: completionHandler)
        self.turnOffNextensioAgent()
        self.attractAll = false
        self.domains = [String]()
        self.subnets = [IPNetwork_v4]()
    }

    override func handleAppMessage(_ messageData: Data, completionHandler: ((Data?) -> Void)? = nil) {
        os_log("handleAppMessage")
        if let handler = completionHandler {
            handler(messageData)
        }
    }

    override func sleep(completionHandler: @escaping () -> Void) {
        os_log("sleep")
        completionHandler()
    }

    override func wake() {
        os_log("wake")
    }
    
    // Tunnel device file descriptor.
    private var tunnelFileDescriptor: Int32? {
        return self.packetFlow.value(forKeyPath: "socket.fileDescriptor") as? Int32
    }
    
    private var interfaceName: String? {
          guard let tunnelFileDescriptor = self.tunnelFileDescriptor else { return nil }

          var buffer = [UInt8](repeating: 0, count: Int(IFNAMSIZ))

          return buffer.withUnsafeMutableBufferPointer { mutableBufferPointer in
              guard let baseAddress = mutableBufferPointer.baseAddress else { return nil }

              var ifnameSize = socklen_t(IFNAMSIZ)
              let result = getsockopt(
                  tunnelFileDescriptor,
                  2 /* SYSPROTO_CONTROL */,
                  2 /* UTUN_OPT_IFNAME */,
                  baseAddress,
                  &ifnameSize)

              if result == 0 {
                  return String(cString: baseAddress)
              } else {
                  return nil
              }
          }
    }
    
    // onboard NextensioAgent (access token)
    private func onboardNextensioAgent(accessToken: String, json: [String:Any]) {
        os_log("processing json data")
        os_log("ConnectID %{public}@", json["connectid"] as! String)
        os_log("Tenant %{public}@", json["tenant"] as! String)
        os_log("Gateway %{public}@", json["gateway"] as! String)
        os_log("Domains count %d", (json["domains"] as! NSMutableArray).count)
        os_log("CA cert count %d", (json["cacert"] as! NSMutableArray).count)
        os_log("UserId %{public}@", json["userid"] as! String)
        os_log("cluster %{public}@", json["cluster"] as! String)
        os_log("UUID %{public}@", uuid)
        os_log("Version %{public}@", last_version)
                
        var registration = CRegistrationInfo()
        
        registration.gateway = UnsafeMutablePointer<Int8>(mutating: (json["gateway"] as! NSString).utf8String)
        registration.access_token = UnsafeMutablePointer<Int8>(mutating: (accessToken as NSString).utf8String)
        registration.connect_id = UnsafeMutablePointer<Int8>(mutating: (json["connectid"] as! NSString).utf8String)
        registration.userid = UnsafeMutablePointer<Int8>(mutating: (json["userid"] as! NSString).utf8String)
        registration.cluster = UnsafeMutablePointer<Int8>(mutating: (json["cluster"] as! NSString).utf8String)
        registration.uuid = UnsafeMutablePointer<Int8>(mutating: (uuid as NSString).utf8String)

        let dom = json["domains"] as! NSMutableArray
        registration.num_domains = Int32(dom.count)
        self.domains = [String]()
        self.subnets = [IPNetwork_v4]()
        self.attractAll = !(json["splittunnel"] as! Bool)
        if (dom.count > 0) {
            registration.domains = UnsafeMutablePointer<UnsafeMutablePointer<Int8>?>.allocate(capacity: dom.count)
            for i in 0..<dom.count {
                let d = dom[i] as! NSDictionary
                if d["name"] as! String != "nextensio-default-internet" {
                    self.domains.append((d["name"] as! String))
                } else {
                    self.attractAll = true
                }
                registration.domains[i] = UnsafeMutablePointer<Int8>(mutating: (d["name"] as! NSString).utf8String)
                do {
                    let net = try IPNetwork_v4(d["name"] as! String)
                    self.subnets.append(net)
                } catch _ {
                }
            }
        } else {
            registration.domains = nil
        }
                    
        registration.num_services = 0
        
        let cert = (json["cacert"] as! NSMutableArray)
        registration.num_cacert = Int32(cert.count)
        registration.ca_cert = UnsafeMutablePointer<Int8>.allocate(capacity: cert.count)
        for i in 0..<cert.count {
            registration.ca_cert[i] = cert[i] as! Int8
        }

        let processInfo:ProcessInfo = ProcessInfo.processInfo

        // Returns the name of the host system
        let hostName:String = processInfo.hostName
        // Returns the version number of the operating system
        let osVerson:OperatingSystemVersion = processInfo.operatingSystemVersion
        let majorVersion:Int = osVerson.majorVersion
        let minorVersion:Int = osVerson.minorVersion
        let patchVersion:Int = osVerson.patchVersion
        // return the operating system name
        let osName:String = processInfo.operatingSystemVersionString
        
        registration.hostname = UnsafeMutablePointer<Int8>(mutating: (hostName as NSString).utf8String)
        registration.model = UnsafeMutablePointer<Int8>(mutating: (self.conf["modelName"] as! NSString).utf8String)
        registration.os_type = UnsafeMutablePointer<Int8>(mutating: ("ios" as NSString).utf8String)
        registration.os_name = UnsafeMutablePointer<Int8>(mutating: (osName as NSString).utf8String)
        registration.os_patch = Int32(patchVersion)
        registration.os_major = Int32(majorVersion)
        registration.os_minor = Int32(minorVersion)

        print("onboarding agent on mac")
        onboard(registration)
                
        // cleanup
        registration.ca_cert.deallocate()
        registration.domains.deallocate()
        
        last_version = json["version"] as! String
        keepalive = json["keepalive"] as! Int
        if keepalive == 0 {
            keepalive = 5*60
        }
        onboarded = true
        force_onboard = false
        
        // Update the NEDNS settings if there are new domains added
        setupVPN()
    }
    
    
    // turn on NextensioAgent
    private func turnOnNextensioAgent() {
        let tunIf : Int32 = self.tunnelFileDescriptor!
        if #available(iOSApplicationExtension 14.0, *) {
            if #available(macOS 11.0, *) {
                os_log("rust-bridge agent_on, tunif: \(tunIf)")
            }
        } else {
            NSLog("rust-bridge agent_on, tunif: \(tunIf)")
        }
        setnonblocking(tunif: tunIf)
        agent_on(tunIf);
    }
    
    // turn off NextensioAgent
    private func turnOffNextensioAgent() {
        os_log("rust-bridge agent_off... ")
        agent_off()
    }
}

// Initialize RegistrationInfo
extension CRegistrationInfo {
    init() {
        self.init(gateway: nil,
                  access_token: nil,
                  connect_id: nil,
                  cluster: nil,
                  domains: nil,
                  num_domains: 0,
                  ca_cert: nil,
                  num_cacert: 0,
                  userid: nil,
                  uuid: nil,
                  services: nil,
                  num_services: 0,
                  hostname: nil,
                  model: nil,
                  os_type: nil,
                  os_name: nil,
                  os_patch: 0,
                  os_major: 0,
                  os_minor: 0)
    }
}

private func setnonblocking(tunif: Int32) -> () {
    var opt = fcntl(tunif, F_GETFL)
    if (opt < 0) {
        os_log("setnonblocking: fcntl(F_GETFL) fail.")
    }
    opt |= O_NONBLOCK;
    if (fcntl(tunif, F_SETFL, opt) < 0) {
        os_log("setnonblocking: fcntl(F_SETFL) fail.");
    }
}
