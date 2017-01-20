package com.github.mpbarnwell;

import com.github.mpbarnwell.tlstest.MQTTConnect;
import com.github.mpbarnwell.tlstest.TLSSocketFactory;
import org.junit.Test;

import java.io.File;
import java.io.PrintStream;
import java.net.URL;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Stream;

import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

public class TLSConnectionTest {

    private final String host = "AU020DOFPRI0E.iot.eu-west-1.amazonaws.com";
    private final int port = 8883;
    private final PrintStream output = System.out;
    private final Path ca;

    // Officially supported ciphers at http://docs.aws.amazon.com/iot/latest/developerguide/iot-security-identity.html
    private final List<String> ciphers = Arrays.asList(
            "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384",
            "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
            "TLS_RSA_WITH_AES_256_CBC_SHA256",
            "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384",
            "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384",
            "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256",
            "TLS_DHE_DSS_WITH_AES_256_CBC_SHA256",
            "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
            "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
            "TLS_RSA_WITH_AES_256_CBC_SHA",
            "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA",
            "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA",
            "TLS_DHE_RSA_WITH_AES_256_CBC_SHA",
            "TLS_DHE_DSS_WITH_AES_256_CBC_SHA",
            "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
            "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
            "TLS_RSA_WITH_AES_128_CBC_SHA256",
            "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256",
            "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256",
            "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256",
            "TLS_DHE_DSS_WITH_AES_128_CBC_SHA256",
            "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
            "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
            "TLS_RSA_WITH_AES_128_CBC_SHA",
            "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA",
            "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA",
            "TLS_DHE_RSA_WITH_AES_128_CBC_SHA",
            "TLS_DHE_DSS_WITH_AES_128_CBC_SHA",
            "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
            "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
            "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
            "TLS_RSA_WITH_AES_256_GCM_SHA384",
            "TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384",
            "TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384",
            "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
            "TLS_DHE_DSS_WITH_AES_256_GCM_SHA384",
            "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
            "TLS_RSA_WITH_AES_128_GCM_SHA256",
            "TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256",
            "TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256",
            "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
            "TLS_DHE_DSS_WITH_AES_128_GCM_SHA256",
            "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA",
            "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA",
            "SSL_RSA_WITH_3DES_EDE_CBC_SHA",
            "TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA",
            "TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA",
            "SSL_DHE_RSA_WITH_3DES_EDE_CBC_SHA",
            "SSL_DHE_DSS_WITH_3DES_EDE_CBC_SHA");

    public TLSConnectionTest() throws Exception {
        URL caCrt = this.getClass().getResource("/VeriSign-Class 3-Public-Primary-Certification-Authority-G5.pem");
        this.ca = new File(caCrt.toURI()).toPath();
    }

    @Test
    public void checkHighStrengthCryptoEnabled() throws Exception {
        TLSSocketFactory socketFactory = new TLSSocketFactory(ca);

        output.println("=== Supported Ciphers ===");
        List<String> supportedCiphers = Arrays.asList(socketFactory.getSupportedCipherSuites());
        supportedCiphers.forEach(output::println);
        output.println();

        output.println("=== Default Ciphers ===");
        Stream.of(socketFactory.getDefaultCipherSuites())
                .forEach(output::println);
        output.println();

        assertTrue(supportedCiphers.contains("TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384"));
    }

    @Test
    public void checkWorkingCiphers() throws Throwable {
        output.println("=== Testing Java version "
                + System.getProperty("java.vendor")
                + " "
                + System.getProperty("java.version")
                + " ===");
        output.println();

        TLSSocketFactory socketFactory = new TLSSocketFactory(ca);

        ciphers.forEach(cipher -> {
            socketFactory.setCipher(cipher);
            output.print(cipher + "... ");
            try {
                MQTTConnect mqttConnect = new MQTTConnect(host, port, socketFactory);
                fail("Expected exception");
            } catch (Throwable e) {
                if ("Received fatal alert: bad_certificate".equals(e.getMessage())) {
                    // This is what we expect when authentication is rejected
                    output.println("Success!");
                } else if ("Received fatal alert: handshake_failure".equals(e.getMessage())) {
                    output.println("Failed: Cipher unsupported by server");
                } else {
                    output.println("Failed (" + e.getClass().getSimpleName() + "): " + e.getMessage());
                }
            }
        });
    }


}
