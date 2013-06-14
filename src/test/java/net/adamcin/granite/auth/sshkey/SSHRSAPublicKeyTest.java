package net.adamcin.granite.auth.sshkey;

import com.jcraft.jsch.Identity;
import com.jcraft.jsch.JSch;
import net.adamcin.commons.testing.junit.FailUtil;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.io.IOUtils;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.FileInputStream;
import java.io.InputStreamReader;
import java.io.Reader;

import static org.junit.Assert.*;
/**
 * Created with IntelliJ IDEA.
 * User: madamcin
 * Date: 6/12/13
 * Time: 11:07 AM
 * To change this template use File | Settings | File Templates.
 */
public class SSHRSAPublicKeyTest {
    private static final Logger LOGGER = LoggerFactory.getLogger(SSHRSAPublicKeyTest.class);

    @Test
    public void testSignature() {
        String sessionId = "sessionId";
        Reader reader = null;
        try {
            SSHPublicKey key = SSHPublicKey.readKeys(
                    new InputStreamReader(
                            new FileInputStream(
                                    SSHKeyTestUtil.getPublicKeyAsFile("b2048")))).get(0);


            MockAuthorizationPacket packet = new MockAuthorizationPacket(sessionId);

            String sig = sign(packet.toString(), "b2048");

            packet.setSignature(sig);

            assertTrue("should round trip", key.verify(packet));
        } catch (Exception e) {
            FailUtil.sprintFail(e);
        } finally {
            IOUtils.closeQuietly(reader);
        }
    }

    public String sign(String dataString, String privPath) {

        JSch jsch = new JSch();
        try {
            jsch.removeAllIdentity();
            File tempPriv = SSHKeyTestUtil.getPrivateKeyAsFile(privPath);
            jsch.addIdentity(tempPriv.getAbsolutePath());

            Identity identity = (Identity) jsch.getIdentityRepository().getIdentities().firstElement();
            byte[] sig = identity.getSignature(dataString.getBytes());
            return Base64.encodeBase64String(sig);
        } catch (Exception e) {
            FailUtil.sprintFail(e);
        }

        return null;
    }
}
