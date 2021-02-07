//
//  PacketType.swift
//

import Foundation

enum IPVersion: UInt8 {
    case IPv4 = 4, IPv6 = 6
}

enum PacketType: UInt8 {
    case TCP = 6, UDP = 17, ICMP = 1
}
