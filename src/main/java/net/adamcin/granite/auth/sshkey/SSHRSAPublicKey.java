package net.adamcin.granite.auth.sshkey;

import com.jcraft.jsch.Buffer;
import com.jcraft.jsch.Signature;
import com.jcraft.jsch.jce.SignatureRSA;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Arrays;

/**
 * Created with IntelliJ IDEA.
 * User: madamcin
 * Date: 6/11/13
 * Time: 4:38 PM
 * To change this template use File | Settings | File Templates.
 */
public final class SSHRSAPublicKey extends SSHPublicKey {
    private static final Logger LOGGER = LoggerFactory.getLogger(SSHRSAPublicKey.class);

    public static final String FORMAT = "ssh-rsa";

    public SSHRSAPublicKey(String format, String encodedKey) {
        super(format, encodedKey);
    }

    @Override
    public Signature getSignature() {
        SignatureRSA signature = new SignatureRSA();

        Buffer buf = new Buffer(this.key);

        try {
            signature.init();
            buf.getString(); // read the format string first
            byte[] e = buf.getMPInt();
            byte[] n = buf.getMPInt();
            signature.setPubKey(e, n);
            return signature;
        } catch (Exception e) {
            LOGGER.error("[getSignature] Exception", e);
        }

        return null;
    }

    @Override
    public boolean equals(Object obj) {
        if (!(obj instanceof SSHRSAPublicKey)) {
            return false;
        }

        SSHRSAPublicKey otherKey = (SSHRSAPublicKey) obj;

        return Arrays.equals(this.key, otherKey.key);
    }

    @Override
    public int hashCode() {
        return FORMAT.hashCode() + Arrays.hashCode(this.key);
    }
}
