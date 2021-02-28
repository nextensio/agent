//
//  Socket.swift
//  nxtTunnel
//
//  Created by Rudy Zulkarnain on 2/7/21.
//

import Foundation
import os.log

@objc protocol SocketStreamDelegate{
    func socketDidConnect(stream:Stream)
    @objc optional func socketDidDisconnect(stream:Stream, message:Data)
    @objc optional func socketDidReceiveMessage(stream:Stream, message:Data)
    @objc optional func socketDidEndConnection()
}

class Socket: NSObject, StreamDelegate {
    weak var delegate:SocketStreamDelegate?

    private let bufferSize = 1400
    private var _host:String?
    private var _port:Int?
    private var _messagesQueue:Array<Data> = [Data]()
    private var _streamHasSpace:Bool = false
    private var inputStream: InputStream?
    private var outputStream: OutputStream?
    var isClosed = false
    var isOpen = false
    var host:String?{
        get{
            return self._host
        }
    }

    var port:Int?{
        get{
            return self._port
        }
    }

    deinit{
        if let inputStr = self.inputStream{
            inputStr.close()
            inputStr.remove(from: .current, forMode: .common)
        }
        if let outputStr = self.outputStream{
            outputStr.close()
            outputStr.remove(from: .current, forMode: .common)
        }
    }

    /**
    Opens streaming for both reading and writing, error will be thrown if you try to send a message and streaming hasn't been opened
    :param: host String with host portion
    :param: port Port
    */
    final func open(host:String!, port:Int!){
        self._host = host
        self._port = port

        if #available(iOS 8.0, *) {
            Stream.getStreamsToHost(withName: self._host!, port: self._port!, inputStream: &inputStream, outputStream: &outputStream)
        } else {
            var inStreamUnmanaged:Unmanaged<CFReadStream>?
            var outStreamUnmanaged:Unmanaged<CFWriteStream>?
            CFStreamCreatePairWithSocketToHost(nil, host as CFString?, UInt32(port), &inStreamUnmanaged, &outStreamUnmanaged)
            inputStream = inStreamUnmanaged?.takeRetainedValue()
            outputStream = outStreamUnmanaged?.takeRetainedValue()
        }

        if inputStream != nil && outputStream != nil {

            inputStream!.delegate = self
            outputStream!.delegate = self

            inputStream!.schedule(in: .current, forMode: .common)
            outputStream!.schedule(in: .current, forMode: .common)

            NSLog("[SCKT]: Open Stream")

            self._messagesQueue = Array()

            inputStream!.open()
            outputStream!.open()
        } else {
            NSLog("[SCKT]: Failed Getting Streams")
        }
    }

    final func close(){
        if let inputStr = self.inputStream{
            inputStr.delegate = nil
            inputStr.close()
            inputStr.remove(from: .current, forMode: .common)
        }
        if let outputStr = self.outputStream{
            outputStr.delegate = nil
            outputStr.close()
            outputStr.remove(from: .current, forMode: .common)
        }
        isClosed = true
    }

    /**
    Stream Delegate Method where we handle errors, read and write data from input and output streams
    :param: stream NStream that called delegate method
    :param: eventCode      Event Code
    */
    private final func stream(stream: Stream, handleEvent eventCode: Stream.Event) {
        switch eventCode {
        case .endEncountered:
            endEncountered(stream: stream)

        case .errorOccurred:
            NSLog("[SCKT]: ErrorOccurred: \(String(describing: stream.streamError?.localizedDescription))")

        case .openCompleted:
            openCompleted(stream: stream)

        case .hasBytesAvailable:
            handleIncommingStream(stream: stream)

        case .hasSpaceAvailable:
            NSLog("space available")
            writeToStream()
            break;

        default:
            break;
        }
    }

    final func endEncountered(stream:Stream){
    }

    final func openCompleted(stream:Stream){
        if(self.inputStream?.streamStatus == .open && self.outputStream?.streamStatus == .open){
            self.isOpen = true
            self.delegate?.socketDidConnect(stream: stream)
        }
    }

    /**
    Reads bytes asynchronously from incomming stream and calls delegate method socketDidReceiveMessage
    :param: stream An InputStream
    */
    final func handleIncommingStream(stream: Stream){
        if let inputStream = stream as? InputStream {
            let buffer = UnsafeMutablePointer<UInt8>.allocate(capacity: self.bufferSize)
            while inputStream.hasBytesAvailable {
                let numberOfBytesRead = inputStream.read(buffer, maxLength: self.bufferSize)
                if numberOfBytesRead < 0, let error = stream.streamError {
                    NSLog(error.localizedDescription)
                    break
                }
                let output = Data(bytes: buffer, count: numberOfBytesRead)
                self.delegate?.socketDidReceiveMessage!(stream: stream, message: output)
            }
        } else {
            NSLog("[SCKT]: \(#function) : Incorrect stream received")
        }

    }

    /**
    If messages exist in _messagesQueue it will remove and it and send it, if there is an error
    it will return the message to the queue
    */
    final func writeToStream(){
        // if _messagesQueue.count > 0 && self.outputStream!.hasSpaceAvailable  {
        if _messagesQueue.count > 0 {
            NSLog("dispatch queue...")
            DispatchQueue.global().async { () -> Void in
                let bytes = self._messagesQueue.removeLast()
                let buffer = [UInt8](bytes)
                if self.outputStream!.write(buffer, maxLength: bytes.count) == -1 {
                    self._messagesQueue.append(bytes)
                }
            }
        }
    }

    final func send(bytes:Data){
        _messagesQueue.insert(bytes, at: 0)

        writeToStream()
    }
}
