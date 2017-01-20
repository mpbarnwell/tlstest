package com.github.mpbarnwell.tlstest;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.openssl.PEMParser;

import javax.net.SocketFactory;
import javax.net.ssl.*;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.InetAddress;
import java.net.Socket;
import java.net.UnknownHostException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.*;
import java.security.cert.CertificateException;

public class TLSSocketFactory extends SSLSocketFactory {

    private static final String TLS_V_1_2 = "TLSv1.2";

    private final SSLSocketFactory sslSocketFactory;

    private String cipher = null;

    public TLSSocketFactory(Path ca) throws
            IOException, KeyStoreException, CertificateException, NoSuchAlgorithmException,
            KeyManagementException, UnrecoverableEntryException {

        // Load CA certificate
        PEMParser parser = new PEMParser(new InputStreamReader(
                new ByteArrayInputStream(Files.readAllBytes(ca))));
        X509CertificateHolder caCert = (X509CertificateHolder) parser.readObject();
        parser.close();

        // Put CA into keystore
        JcaX509CertificateConverter certConverter = new JcaX509CertificateConverter();
//        certConverter.setProvider("BC");
        KeyStore caKs = KeyStore.getInstance(KeyStore.getDefaultType());
        caKs.load(null, null);
        caKs.setCertificateEntry("ca-certificate",
                certConverter.getCertificate(caCert));

        TrustManagerFactory tmf = TrustManagerFactory
                .getInstance(TrustManagerFactory.getDefaultAlgorithm());

        tmf.init(caKs);

        SSLContext context = SSLContext.getInstance(TLS_V_1_2);
//        KeyManagerFactory managerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
//        managerFactory.init(ks, "changeit".toCharArray());
        context.init(null, tmf.getTrustManagers(), null);

        this.sslSocketFactory = context.getSocketFactory();
    }

    public void setCipher(String cipher) {
        this.cipher = cipher;
    }

    @Override
    public String[] getDefaultCipherSuites() {
        return sslSocketFactory.getDefaultCipherSuites();
    }

    @Override
    public String[] getSupportedCipherSuites() {
        return sslSocketFactory.getSupportedCipherSuites();
    }

    @Override
    public Socket createSocket() throws IOException {
        return ensureTls(sslSocketFactory.createSocket());
    }

    @Override
    public Socket createSocket(Socket s, String host, int port, boolean autoClose) throws IOException {
        return ensureTls(sslSocketFactory.createSocket(s, host, port, autoClose));
    }

    @Override
    public Socket createSocket(String host, int port) throws IOException, UnknownHostException {
        return ensureTls(sslSocketFactory.createSocket(host, port));
    }

    @Override
    public Socket createSocket(String host, int port, InetAddress localHost, int localPort)
            throws IOException, UnknownHostException {
        return ensureTls(sslSocketFactory.createSocket(host, port, localHost, localPort));
    }

    @Override
    public Socket createSocket(InetAddress host, int port) throws IOException {
        return ensureTls(sslSocketFactory.createSocket(host, port));
    }

    @Override
    public Socket createSocket(InetAddress address, int port, InetAddress localAddress, int localPort)
            throws IOException {
        return ensureTls(sslSocketFactory.createSocket(address, port, localAddress, localPort));
    }

    /**
     * Enable TLS 1.2 on any socket created by the underlying SSL Socket
     * Factory.
     *
     * @param socket
     *            newly created socket which may not have TLS 1.2 enabled.
     * @return TLS 1.2 enabled socket.
     */
    private Socket ensureTls(Socket socket) {
        if (socket != null && (socket instanceof SSLSocket)) {
            ((SSLSocket) socket).setEnabledProtocols(new String[] { TLS_V_1_2 });

            // Ensure hostname is validated against the CN in the certificate
            SSLParameters sslParams = new SSLParameters();
            sslParams.setEndpointIdentificationAlgorithm("HTTPS");
            ((SSLSocket) socket).setSSLParameters(sslParams);

            if (cipher != null) {
                ((SSLSocket) socket).setEnabledCipherSuites(new String[] { cipher });
            }
        }
        return socket;
    }
}
