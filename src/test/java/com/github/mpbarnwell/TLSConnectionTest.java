package com.github.mpbarnwell;

import com.github.mpbarnwell.tlstest.MQTTConnect;
import com.github.mpbarnwell.tlstest.TLSSocketFactory;
import org.junit.Test;

import javax.net.ssl.SSLHandshakeException;
import java.io.File;
import java.io.PrintStream;
import java.net.URL;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Stream;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

public class TLSConnectionTest {

    private final String endpoint = "ssl://AU020DOFPRI0E.iot.eu-west-1.amazonaws.com:8883";
    private final PrintStream output = System.out;
    private final Path ca;

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
        TLSSocketFactory socketFactory = new TLSSocketFactory(ca);
        try {
            MQTTConnect mqttConnect = new MQTTConnect(endpoint, socketFactory);
            fail("Expected exception");
        } catch (SSLHandshakeException e) {
            // This is what we expect when authentication is rejected
            assertEquals("Received fatal alert: bad_certificate", e.getMessage());
        }
    }


}
