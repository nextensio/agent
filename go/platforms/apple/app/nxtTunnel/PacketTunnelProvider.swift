//
//  PacketTunnelProvider.swift
//  Nxt App Tunnel
//
//  Created by Rudy Zulkarnain on 1/22/21.
//

import NetworkExtension
import os.log

class PacketTunnelProvider: NEPacketTunnelProvider {
    var session: NWUDPSession? = nil
    var conf = [String: AnyObject]()
    var pendingStartCompletion: ((NSError?) -> Void)?
    
    func tunToUDP() {
        self.packetFlow.readPackets { (packets: [Data], protocols: [NSNumber]) in
            for packet in packets {
                logPacketSrcDestIP(packet, "original")
                logPacket(packet, prefix: "Original")

                self.session?.writeDatagram(packet, completionHandler: { (error: Error?) in
                    if let error = error {
                        NSLog("Failed in writeDatagram \(error)")
                        self.setupUDPSession()
                        return
                    }
                })
            }
            // Recursive to keep reading
            self.tunToUDP()
        }
    }

    func udpToTun() {
        // It's callback here
        NSLog("udpToTun")

        session?.setReadHandler({ (_packets: [Data]?, error: Error?) -> Void in
            if let packets = _packets {
                self.packetFlow.writePackets(packets, withProtocols: [NSNumber](repeating: AF_INET as NSNumber, count: packets.count))
            }
        }, maxDatagrams: NSIntegerMax)
    }
    
    // These are core methods for Nextensio VPN tunnelling
    //   - read from tun device, override, write to tun device
    func tunProxy() {
        NSLog("proxy tun packets...")
        
        self.packetFlow.readPackets { (packets: [Data], protocols: [NSNumber]) in
            for packet in packets {
                let proto = protocolNumber(for: packet)
                
                logPacketSrcDestIP(packet, "original")

                NSLog("proto: \(proto.uint8Value), tcp: \(PacketType.TCP.rawValue)")
                if (protocolType(for: packet) == PacketType.TCP) {
                    var overridePacket = packet // make it mutuable
                    overrideDestAddr(&overridePacket)
                    logPacketSrcDestIP(overridePacket, "mapped")
                    self.packetFlow.writePackets([overridePacket], withProtocols: [proto])

                }
                else {
                    self.packetFlow.writePackets([packet], withProtocols: [proto])
                }
            }
            // Recursive to keep reading
            self.tunProxy()
        }
    }
    
    func setupUDPSession() {
        if self.session != nil {
            self.reasserting = true
            self.session = nil
        }
        let serverAddress = self.conf["server"] as! String
        let serverPort = self.conf["port"] as! String
        self.reasserting = false
        
        NSLog("Setup UDP session to \(serverAddress) \(serverPort)")

        self.session = self.createUDPSession(to: NWHostEndpoint(hostname: serverAddress, port: serverPort), from: nil)
        self.setupPacketTunnelNetworkSettings()
    }

    func setupPacketTunnelNetworkSettings() {
        
        // the `tunnelRemoteAddress` is meaningless because we are not creating a tunnel.
        let networkSettings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: self.protocolConfiguration.serverAddress!)
        
        // Refers to NEIPv4Settings#includedRoutes or NEIPv4Settings#excludedRoutes,
        // which can be used as basic whitelist/blacklist routing.
        
        let ipv4Settings = NEIPv4Settings(addresses: ["10.0.0.1"], subnetMasks: ["255.255.0.0"])
        ipv4Settings.includedRoutes = [
            //NEIPv4Route.default()
            NEIPv4Route(destinationAddress: "10.0.0.2", subnetMask: "255.255.255.255")
        ]
        ipv4Settings.excludedRoutes = [
            NEIPv4Route(destinationAddress: "10.0.0.0", subnetMask: "255.0.0.0"),
            NEIPv4Route(destinationAddress: "127.0.0.0", subnetMask: "255.0.0.0"),
            NEIPv4Route(destinationAddress: "192.168.0.0", subnetMask: "255.255.0.0"),
        ]
        networkSettings.ipv4Settings = ipv4Settings
        networkSettings.mtu = Int(conf["mtu"] as! String) as NSNumber?

        let dnsSettings = NEDNSSettings(servers: (conf["dns"] as! String).components(separatedBy: ","))
        // This overrides system DNS settings
        dnsSettings.matchDomains = [""]
        networkSettings.dnsSettings = dnsSettings
        
        // Save the settings
        self.setTunnelNetworkSettings(networkSettings) { error in
            self.pendingStartCompletion?(nil)
            self.pendingStartCompletion = nil
            
            // self.udpToTun()
        }
    }

    override func startTunnel(options: [String : NSObject]?, completionHandler: @escaping (Error?) -> Void) {
        NSLog("tunnel getting provider protocol")
        conf = (self.protocolConfiguration as! NETunnelProviderProtocol).providerConfiguration! as [String : AnyObject]

        NSLog("tunnel saving completion handler")
        pendingStartCompletion = completionHandler
        
        //NSLog("tunnel setup packet tunnel network settings")
        self.setupPacketTunnelNetworkSettings()
        
        // If you are going to be reading directly from this fd, be aware that iOS's tun implementatio appends a 4-byte protocol information header to each packet. If we had more control we would create the tun with the IFF_NO_PI option to prevent this, but instead we just throw away the first four bytes.
        
        let utunstr = String(format: "%d", self.tunnelFileDescriptor!)
        NSLog("tunnel fd = \(utunstr)")
                
        self.tunProxy()

//        self.setupUDPSession()
//        self.tunToUDP()
    }

    override func stopTunnel(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        NSLog("tunnel stop")
        session?.cancel()
        super.stopTunnel(with: reason, completionHandler: completionHandler)
    }

    override func handleAppMessage(_ messageData: Data, completionHandler: ((Data?) -> Void)? = nil) {
        NSLog("handleAppMessage")
        
        if let handler = completionHandler {
            handler(messageData)
        }
    }

    override func sleep(completionHandler: @escaping () -> Void) {
        completionHandler()
    }

    override func wake() {
    }
    
    /// Tunnel device file descriptor.
    private var tunnelFileDescriptor: Int32? {
        return self.packetFlow.value(forKeyPath: "socket.fileDescriptor") as? Int32
    }
    
    public var interfaceName: String? {
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
}

private func protocolType(for packet: Data) -> PacketType {
    let proto = UInt8(packet[9]) // IPv4 Header protocol type
    
    if (proto == 1) { return PacketType.ICMP }
    else if (proto == 6) { return PacketType.TCP }
    else {
        return PacketType.UDP
    }
}

private func protocolNumber(for packet: Data) -> NSNumber {
    guard !packet.isEmpty else {
        return AF_INET as NSNumber
    }

    // The first 4 bits identify the IP version
    let ipVersion = (packet[0] & 0xf0) >> 4
    return (ipVersion == 6) ? AF_INET6 as NSNumber : AF_INET as NSNumber
}

private func bytesConvertToHexstring(byte : [UInt8]) -> String {
    var string = ""

    for val in byte {
        //getBytes(&byte, range: NSMakeRange(i, 1))
        string = string + String(format: "%02X", val)
    }

    return string
}

private func logPacket(_ packet: Data, prefix: String) -> Void {
    let byteArray = [UInt8](packet) // transfer packet to array
    NSLog("\(prefix) packet %@", bytesConvertToHexstring(byte: byteArray))
}

private func logPacketSrcDestIP(_ packet: Data, _ prefix: String) -> Void {
    guard !packet.isEmpty else {
        return
    }
    let byteArray = [UInt8](packet) // transfer packet to array
    // NSLog("Byte array %@", byteArray)

    let proto = String(format: "%d", byteArray[9])
    let srcIP = String(format: "%d.%d.%d.%d", byteArray[12], byteArray[13], byteArray[14], byteArray[15])
    let destIP = String(format: "%d.%d.%d.%d", byteArray[16], byteArray[17], byteArray[18], byteArray[19])
    NSLog("\(prefix) utun proto: \(proto), srcIP: \(srcIP), destIP: \(destIP)")
}

private func computeIPCheckSum(_ packet: Data) -> [UInt8] {
    var st = String(format:"0x%02X,0x%02X, count:%d", packet[10], packet[11], packet.count)
    NSLog("Compute IP Checksum... original checksum=\(st)")

    // Compute IP Checksum
    // https://en.wikipedia.org/wiki/IPv4_header_checksum

    var sum32: UInt32 = 0
    var loop: UInt8 = 0
    for i in stride(from: 0, to: 19, by: 2) { // 20 bytes header, 10 16bits
        let u16: UInt16 = (UInt16(packet[i]) << 8) + UInt16(packet[i+1]) // preserved the network order
//        st = String(format:"i:%d, 0x%02X,0x%02X, uint16: 0x%02X", i, packet[i], packet[i+1], u16)
//        NSLog("Compute IP Checksum...\(st)")

        if (i != 10) { // don't add checksum into the sum32
            sum32 += UInt32(u16)
        }
        loop += 1
    }

    // st = String(format:"0x%02X", sum32)
    // NSLog("Compute Checksum... loop=\(loop), sum32=\(st)")

    while (sum32 > 0xffff) {
        sum32 = (sum32 >> 16) + (sum32 & 0xFFFF);
    }

    // st = String(format:"0x%02X", sum32)
    // NSLog("Compute Checksum... after folding, sum32=\(st)")

    var checksum = [UInt8](repeating: 0, count: 2)
    checksum[0] = UInt8(sum32 >> 8 & 0x00ff)
    checksum[1] = UInt8(sum32 & 0x00ff)
    st = String(format:"0x%02X,0x%02X, 1': 0x%02X,0x%02X", checksum[0], checksum[1], ~checksum[0], ~checksum[1])
    NSLog("Compute IP Checksum... computed checksum=\(st)")
    
    return checksum
}

private func computeTCPCheckSum(_ packet: Data) -> [UInt8] {
    var st = String(format:"0x%02X,0x%02X, count:%d", packet[36], packet[37], packet.count)
    NSLog("Compute TCP Checksum... original checksum=\(st)")
    
    var sum32: UInt32 = 0

    // Compute Pseudo Header
    // http://www.tcpipguide.com/free/t_TCPChecksumCalculationandtheTCPPseudoHeader-2.htm

    // Compute Pseudo Header: SRCIP + DSTIP
    for i in stride(from: 12, to: 19, by: 2) { //
        let u16: UInt16 = (UInt16(packet[i]) << 8) + UInt16(packet[i+1]) // preserved the network order
//        st = String(format:"i:%d, 0x%02X,0x%02X, uint16: 0x%02X, %d", i, packet[i], packet[i+1], u16, u16)
//        NSLog("Compute TCP Checksum...src/dst IP \(st)")
        sum32 += UInt32(u16)
    }
    
//    st = String(format:"src+dst sum32: 0x%02X (%d)", sum32, sum32)
//    NSLog("Compute TCP Checksum... \(st)")
    
    // TCP Proto
    sum32 += UInt32(PacketType.TCP.rawValue)
    
//    st = String(format:"proto sum32: 0x%02X (%d)", sum32, sum32)
//    NSLog("Compute TCP Checksum... \(st)")

    // TCP Segment Length
    let IP_HEADER_SIZE: Int = 20
    sum32 += UInt32(packet.count - IP_HEADER_SIZE)
    
//    st = String(format:"0x%02X, %d", sum32, sum32)
//    NSLog("Compute TCP Checksum... pseudo header sum=\(st)")
    
    // TCPHeader + TCPData
    for i in stride(from: 20, to: packet.count-1, by: 2) { // 20 - 64 bytes header, 10 16bits
        let u16: UInt16 = (UInt16(packet[i]) << 8) + UInt16(packet[i+1]) // preserved the network order
//        st = String(format:"i:%d, 0x%02X,0x%02X, uint16: 0x%02X", i, packet[i], packet[i+1], u16)
//        NSLog("Compute TCP Checksum...\(st)")
        if (i != 36) { // don't add checksum into the sum32
            sum32 += UInt32(u16)
        }
    }

//    st = String(format:"0x%02X", sum32)
//    NSLog("Compute TCP Checksum... sum32=\(st)")

    while (sum32 > 0xffff) {
        sum32 = (sum32 >> 16) + (sum32 & 0xFFFF);
    }

//    st = String(format:"0x%02X", sum32)
//    NSLog("Compute TCP Checksum... after folding, sum32=\(st)")

    var checksum = [UInt8](repeating: 0, count: 2)
    checksum[0] = UInt8(sum32 >> 8 & 0x00ff)
    checksum[1] = UInt8(sum32 & 0x00ff)
    st = String(format:"0x%02X,0x%02X, 1': 0x%02X,0x%02X", checksum[0], checksum[1], ~checksum[0], ~checksum[1])
    NSLog("Compute TCP Checksum... computed checksum=\(st)")
    
    return checksum
}

private func overrideDestAddr(_ newPacket: inout Data) -> Void {
    guard !newPacket.isEmpty else {
        return
    }
    
    logPacket(newPacket, prefix: "Original")
        
    _ = computeIPCheckSum(newPacket) // validate algorithm is correct
    _ = computeTCPCheckSum(newPacket) // validate algorithm is correct
    
    NSLog("Mapped packet srcIP to destIP")
    newPacket[12] = newPacket[16]
    newPacket[13] = newPacket[17]
    newPacket[14] = newPacket[18]
    newPacket[15] = newPacket[19]
    NSLog("Mapped packet destIP to 127.0.0.1")
    newPacket[16] = 127
    newPacket[17] = 0
    newPacket[18] = 0
    newPacket[19] = 1
    
    // recomputeCheckSum(newPacket)

    // Re-compute IP Checksum
    var checksum = [UInt8](repeating: 0, count: 2)
    var tcpChecksum = [UInt8](repeating: 0, count: 2)

    checksum = computeIPCheckSum(newPacket)
    tcpChecksum = computeTCPCheckSum(newPacket)

    // Put it back to the checksum
    newPacket[10] = ~checksum[0]
    newPacket[11] = ~checksum[1]
    
    // Put it back to the checksum
    newPacket[36] = ~tcpChecksum[0]
    newPacket[37] = ~tcpChecksum[1]
    
    logPacket(newPacket, prefix: "Mapped")
}
