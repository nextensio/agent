//
//  PacketTunnelProvider.swift
//  NextensioPacketTunnel
//
//  Created by Rudy Zulkarnain on 2/7/21.
//

import NetworkExtension
import os.log

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

    override init() {
        super.init()
    }
    
    private func onboardController(accessToken: String) {
        os_log("onboard Controller")
        
        //create the url with NSURL
        let url = URL(string: "https://server.nextensio.net:8080/api/v1/global/get/onboard")! //change the url
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
                os_log("url error")
                return
            }
            guard let data = data else {
                os_log("data error")
                return
            }
            do {
                //create json object from data
                if let onboard = try JSONSerialization.jsonObject(with: data, options: .mutableContainers) as? [String: Any] {
                    //onBoard Agent
                    self.onboardNextensioAgent(accessToken: accessToken, json: onboard)
                }
                //onBoard Agent
            } catch _ {
                os_log("error in json serialization")
            }
        })
        task.resume()
    }
    
    private func setupVPN() {
        // the `tunnelRemoteAddress` is meaningless because we are not creating a tunnel.
        let networkSettings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: self.protocolConfiguration.serverAddress!)
        
        // Refers to NEIPv4Settings#includedRoutes or NEIPv4Settings#excludedRoutes,
        // which can be used as basic whitelist/blacklist routing.
        
        let ipv4Settings = NEIPv4Settings(addresses: ["169.254.2.1"], subnetMasks: ["255.255.255.0"])
        
        ipv4Settings.includedRoutes = [
            NEIPv4Route.default()
        ]
        ipv4Settings.excludedRoutes = [
            NEIPv4Route(destinationAddress: "127.0.0.1", subnetMask: "255.255.0.0"),
            NEIPv4Route(destinationAddress: "192.168.0.0", subnetMask: "255.255.0.0"),
        ]
        networkSettings.ipv4Settings = ipv4Settings
        networkSettings.mtu = Int(conf["mtu"] as! String) as NSNumber?

        let dnsSettings = NEDNSSettings(servers: (conf["dns"] as! String).components(separatedBy: ","))
        // This overrides system DNS settings
        dnsSettings.matchDomains = [""]
        networkSettings.dnsSettings = dnsSettings
        
        let access = (conf["access"] as! String)
        // let refresh = (conf["refresh"] as! String)
         
        // Save the settings
        self.setTunnelNetworkSettings(networkSettings) { error in
            self.pendingStartCompletion?(nil)
            self.pendingStartCompletion = nil
            
            if (self.conf["direct"] as! String) == "false" {
                self.onboardController(accessToken: access)
            }
            
            self.startAgent()
            
            DispatchQueue.main.asyncAfter(deadline: .now() + 5, execute: {
                self.turnOnNextensioAgent()
            })
        }
    }
    
    func startAgent() {
          let t = Thread(target: self, selector: #selector(runner(msg:)), object: "nextensio.worker")
          t.start()
      }

    @objc func runner(msg: String) {
        let direct : UInt = 1
        if #available(iOSApplicationExtension 14.0, *) {
            os_log("rust-bridge agent_init: \(direct)")
        } else {
            NSLog("rust-bridge agent_init: \(direct)")
        }
        agent_init(1 /*apple*/, direct)
    }

    override func startTunnel(options: [String : NSObject]?, completionHandler: @escaping (Error?) -> Void) {
        
        os_log("startTunnel using Network Extension configuration")
        self.conf = (self.protocolConfiguration as! NETunnelProviderProtocol).providerConfiguration! as [String : AnyObject]

        self.pendingStartCompletion = completionHandler
        self.setupVPN()
    }

    override func stopTunnel(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        super.stopTunnel(with: reason, completionHandler: completionHandler)
        self.turnOffNextensioAgent()
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

        var registration = CRegistrationInfo()
        
        os_log("rust-bridge registration info")

        registration.host = UnsafeMutablePointer<Int8>(mutating: (json["gateway"] as! NSString).utf8String)
        registration.access_token = UnsafeMutablePointer<Int8>(mutating: (accessToken as NSString).utf8String)
        registration.connect_id = UnsafeMutablePointer<Int8>(mutating: (json["connectid"] as! NSString).utf8String)
        registration.userid = UnsafeMutablePointer<Int8>(mutating: (json["userid"] as! NSString).utf8String)
        registration.uuid = UnsafeMutablePointer<Int8>(mutating: (UUID().uuidString as NSString).utf8String)
        registration.domains = UnsafeMutablePointer<Int8>(mutating: ("" as NSString).utf8String)
        registration.num_domains = 1
        registration.services = UnsafeMutablePointer<Int8>(mutating: (json["connectid"] as! NSString).utf8String)
        registration.num_services = 1
        let arr = (json["cacert"] as! NSMutableArray)
        let cacert = UnsafeMutablePointer<Int8>.allocate(capacity: arr.count)
        for i in 0..<arr.count {
            cacert[i] = arr[i] as! Int8
        }
        // registration.ca_cert = UnsafeMutablePointer<Int8>(mutating: (json["ca_cert"] as! NSString).utf8String)
        registration.num_cacert = 1
        
        // onboard(registration)
    }
    
    // turn on NextensioAgent
    private func turnOnNextensioAgent() {
        let tunIf : Int32 = self.tunnelFileDescriptor!
        if #available(iOSApplicationExtension 14.0, *) {
            os_log("rust-bridge agent_on, tunif: \(tunIf)")
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
        let emptyStr = UnsafeMutablePointer<Int8>(mutating: ("" as NSString).utf8String)
        self.init(host: emptyStr,
                  access_token: emptyStr,
                  connect_id: emptyStr,
                  domains: emptyStr,
                  num_domains: 0,
                  ca_cert: emptyStr,
                  num_cacert: 0,
                  userid: emptyStr,
                  uuid: emptyStr,
                  services: emptyStr,
                  num_services: 0)
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
