package com.github.mpbarnwell.tlstest;

import com.google.common.base.Throwables;
import org.eclipse.paho.client.mqttv3.IMqttToken;
import org.eclipse.paho.client.mqttv3.MqttAsyncClient;
import org.eclipse.paho.client.mqttv3.MqttConnectOptions;
import org.eclipse.paho.client.mqttv3.MqttException;

import javax.net.SocketFactory;

public class MQTTConnect {

    public MQTTConnect(String endpoint, SocketFactory socketFactory) throws Throwable {
        MqttConnectOptions conOpt = new MqttConnectOptions();
        conOpt.setSocketFactory(socketFactory);

        try {
            MqttAsyncClient client = new MqttAsyncClient(endpoint, "client");
            IMqttToken token = client.connect(conOpt);
            token.waitForCompletion(10000);
            client.close();
        } catch (MqttException e) {
            // Unwrap exceptions
            throw Throwables.getRootCause(e);
        }
    }

}
