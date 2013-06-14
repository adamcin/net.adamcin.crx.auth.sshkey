package net.adamcin.granite.auth.sshkey;

import com.jcraft.jsch.Signature;
import org.apache.commons.codec.binary.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.Reader;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

abstract class SSHPublicKey {

    private static final Logger LOGGER = LoggerFactory.getLogger(SSHKeyAuthPacketImpl.class);
    private static final String CHARSET = "ISO-8859-1";
    private static final Pattern KEY_PATTERN = Pattern.compile("^([^\\s]+)\\s+([^\\s]+)(\\s|$)");
    private static final int GROUP_FORMAT = 1;
    private static final int GROUP_KEY = 2;

    protected final String format;
    protected final String encodedKey;
    protected final byte[] key;

    protected SSHPublicKey(String format, String encodedKey) {
        this.format = format;
        this.encodedKey = encodedKey;
        this.key = Base64.decodeBase64(encodedKey);
    }

    public static boolean verify(SSHKeyAuthPacket packet) {
        if (packet != null) {
            try {
                SSHPublicKey key = createKey(packet.getFormat(), packet.getKey());

                Signature sig = key.getSignature();
                sig.update(packet.toString().getBytes());
                return sig.verify(Base64.decodeBase64(packet.getSignature()));
            } catch (Exception e) {
                LOGGER.info("[verify] exception occurred", e);
            }
        }
        return false;
    }

    public abstract Signature getSignature();

    @Override
    public abstract boolean equals(Object obj);

    @Override
    public abstract int hashCode();

    @Override
    public String toString() {
        return format + " " + encodedKey;
    }

    public static List<SSHPublicKey> readKeys(Reader reader) throws IOException {

        List<SSHPublicKey> keys = new ArrayList<SSHPublicKey>();
        BufferedReader bufferedReader = new BufferedReader(reader);

        String line;
        while ((line = bufferedReader.readLine()) != null) {
            SSHPublicKey key = readKey(line);
            if (key != null) {
                keys.add(key);
            }
        }

        return Collections.unmodifiableList(keys);
    }

    public static SSHPublicKey readKey(String publicKeyString) {
        if (publicKeyString != null) {
            Matcher matcher = KEY_PATTERN.matcher(publicKeyString);
            if (matcher.find()) {
                String format = matcher.group(GROUP_FORMAT);
                String key = matcher.group(GROUP_KEY);
                return createKey(format, key);
            }
        }
        return null;
    }

    public static SSHPublicKey createKey(String format, String encodedKey) {
        if ("ssh-dss".equals(format)) {
            //keys.add(new );
        } else if (SSHRSAPublicKey.FORMAT.equals(format)) {
            return new SSHRSAPublicKey(format, encodedKey);
        }

        return null;
    }
}
