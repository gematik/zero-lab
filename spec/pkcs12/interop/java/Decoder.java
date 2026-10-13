/*
 * Copyright (Change Date see Readme), gematik GmbH
 *
 * Licensed under the EUPL, Version 1.2 or - as soon they will be approved by the
 * European Commission – subsequent versions of the EUPL (the "Licence").
 * You may not use this work except in compliance with the Licence.
 *
 * You find a copy of the Licence in the "Licence" file or at
 * https://joinup.ec.europa.eu/collection/eupl/eupl-text-eupl-12
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either expressed or implied.
 * In case of changes by gematik find details in the "Readme" file.
 *
 * See the Licence for the specific language governing permissions and limitations under the Licence.
 *
 * *******
 *
 * For additional notes and disclaimer from gematik and in case of changes by gematik,
 * find details in the "Readme" file.
 */

// JDK adapter of the PKCS#12 conformance harness:
//
//     java Decoder.java decode --password-file FILE P12
//
// Writes the JSON of spec/pkcs12/CONFORMANCE.md (command-line contract) for
// java.security.KeyStore of type PKCS12. The KeyStore reports no reason for a
// failure, so the harness runs it with -coarse. Keys are re-encoded by the
// JDK and match by the public key of their certificate.

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HexFormat;
import java.util.List;

public class Decoder {
    public static void main(String[] args) throws Exception {
        if (args.length != 4 || !args[0].equals("decode") || !args[1].equals("--password-file")) {
            System.err.println("usage: java Decoder.java decode --password-file FILE P12");
            System.exit(2);
        }
        char[] password = new String(Files.readAllBytes(Path.of(args[2])), StandardCharsets.UTF_8).toCharArray();
        byte[] data = Files.readAllBytes(Path.of(args[3]));
        System.out.println(decode(data, password));
    }

    static String decode(byte[] data, char[] password) {
        List<String> certs = new ArrayList<>();
        List<String> keys = new ArrayList<>();
        List<String> pairs = new ArrayList<>();
        try {
            KeyStore ks = KeyStore.getInstance("PKCS12");
            ks.load(new ByteArrayInputStream(data), password);
            List<String> seen = new ArrayList<>();
            for (String alias : Collections.list(ks.aliases())) {
                String name = json(alias);
                if (ks.isKeyEntry(alias)) {
                    ks.getKey(alias, password); // decrypts the key
                    Certificate[] chain = ks.getCertificateChain(alias);
                    String spki = chain != null && chain.length > 0 ? sha256(chain[0].getPublicKey().getEncoded()) : "";
                    keys.add("{\"public_key_sha256\":\"" + spki + "\",\"friendly_name\":" + name + "}");
                    if (chain != null) {
                        for (int i = 0; i < chain.length; i++) {
                            String d = sha256(chain[i].getEncoded());
                            if (seen.contains(d)) continue;
                            seen.add(d);
                            certs.add("{\"sha256\":\"" + d + "\"" + (i == 0 ? ",\"friendly_name\":" + name : "") + "}");
                            if (i == 0) pairs.add("[" + (certs.size() - 1) + "," + (keys.size() - 1) + "]");
                        }
                    }
                } else if (ks.isCertificateEntry(alias)) {
                    String d = sha256(ks.getCertificate(alias).getEncoded());
                    if (seen.contains(d)) continue;
                    seen.add(d);
                    certs.add("{\"sha256\":\"" + d + "\",\"friendly_name\":" + name + "}");
                }
            }
        } catch (Exception e) {
            return "{\"code\":\"error\",\"detail\":" + json(String.valueOf(e)) + ",\"certificates\":[],\"keys\":[],\"pairs\":[],\"mac\":null}";
        }
        return "{\"code\":\"ok\",\"certificates\":[" + String.join(",", certs) + "],\"keys\":["
                + String.join(",", keys) + "],\"pairs\":[" + String.join(",", pairs) + "],\"mac\":null}";
    }

    static String sha256(byte[] b) throws Exception {
        return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(b));
    }

    static String json(String s) {
        StringBuilder out = new StringBuilder("\"");
        for (char c : s.toCharArray()) {
            switch (c) {
                case '"' -> out.append("\\\"");
                case '\\' -> out.append("\\\\");
                default -> {
                    if (c < 0x20) out.append(String.format("\\u%04x", (int) c));
                    else out.append(c);
                }
            }
        }
        return out.append('"').toString();
    }
}
