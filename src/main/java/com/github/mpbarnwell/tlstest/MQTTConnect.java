package com.github.mpbarnwell.tlstest;

import javax.net.SocketFactory;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketAddress;

public class MQTTConnect {

    public MQTTConnect(String host, int port, SocketFactory socketFactory) throws Throwable {
        try (Socket socket = socketFactory.createSocket()) {
            SocketAddress sockaddr = new InetSocketAddress(host, port);
            socket.connect(sockaddr, 10000);
            socket.getInputStream().read(); // Ensure we connect
        }
    }

}
