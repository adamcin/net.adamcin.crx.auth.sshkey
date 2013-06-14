package net.adamcin.granite.auth.sshkey;

import net.adamcin.commons.testing.junit.FailUtil;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.io.IOUtils;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.crypto.Signer;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.signers.RSADigestSigner;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;

import static org.junit.Assert.*;

public class RSAAuthPacketImplTest {
    private static final Logger LOGGER = LoggerFactory.getLogger(RSAAuthPacketImplTest.class);

    /*
    @Test
    public void testParse() {
        String sessionId = "sessionId";
        String key = SSHKeyTestUtil.B2048_PUBKEY;
        String signature = "somesig";

        String packetString = sessionId + " " + key + " " + signature;

        SSHKeyAuthPacketImpl packet = SSHKeyAuthPacketImpl.parse(packetString);

        assertNotNull("packet should not be null", packet);
        assertEquals("sessionId should match", sessionId, packet.getSessionId());
        assertEquals("key should match", key, packet.getKey());
        assertEquals("signature should match", signature, packet.getSignature());
    }
    */

    public void testVerify() {
        String sessionId = "sessionId";
        String key = SSHKeyTestUtil.B2048_PUBKEY;
        String sig = sign(sessionId, key, getPEMKeyPairFromResource("/b2048/id_rsa"));

        LOGGER.error("signature: {}", sig);
        SSHKeyAuthPacketImpl packet = new SSHKeyAuthPacketImpl(sessionId, "admin", "ssh-rsa", key, sig);
        assertTrue("Packet should verify", SSHPublicKey.verify(packet));
    }

    public String sign(String sessionId, String publicKey, PEMKeyPair pemKeyPair) {
        try {
            Signer signer = new RSADigestSigner(new SHA1Digest());

            signer.init(true, PrivateKeyFactory.createKey(pemKeyPair.getPrivateKeyInfo()));
            byte[] data = sessionId.getBytes("ISO-8859-1");
            signer.update(data, 0, data.length);

            Signer verifier = new RSADigestSigner(new SHA1Digest());
            verifier.init(false, PublicKeyFactory.createKey(pemKeyPair.getPublicKeyInfo()));
            verifier.update(data, 0, data.length);
            assertTrue("BC should roundtrip already", verifier.verifySignature(signer.generateSignature()));
            return Base64.encodeBase64String(signer.generateSignature());
            /*
            byte[] encoded = Base64.decodeBase64(privateKey);
            PKCS8EncodedKeySpec privateSpec = new PKCS8EncodedKeySpec(encoded);
            KeyFactory kf = KeyFactory.getInstance("RSA");
            PrivateKey privKey = kf.generatePrivate(privateSpec);

            Signature sig = Signature.getInstance("SHA1withRSA");
            sig.initSign(privKey);
            sig.update();
            */
        } catch (Exception e) {
            FailUtil.sprintFail(e);
        }
        return null;
    }

    public PEMKeyPair getPEMKeyPairFromResource(String name) {
        InputStream stream = null;
        try {
            stream = getClass().getResourceAsStream(name);
            Object parsed = new PEMParser(new InputStreamReader(stream)).readObject();
            if (parsed instanceof PEMKeyPair) {
                return (PEMKeyPair) parsed;
            } else {
                return null;
            }
        } catch (IOException e) {
            LOGGER.error("failed to read private key");
            return null;
        } finally {
            IOUtils.closeQuietly(stream);
        }
    }

    public PrivateKeyInfo getPKCS8KeyFromResource(String name) {
        InputStream stream = null;
        try {
            stream = getClass().getResourceAsStream(name);
            Object parsed = new PEMParser(new InputStreamReader(stream)).readObject();
            if (parsed instanceof PrivateKeyInfo) {
                return (PrivateKeyInfo) parsed;
            } else if (parsed instanceof PEMKeyPair) {
                return ((PEMKeyPair) parsed).getPrivateKeyInfo();
            } else {
                return null;
            }
        } catch (IOException e) {
            LOGGER.error("failed to read private key");
            return null;
        } finally {
            IOUtils.closeQuietly(stream);
        }
    }
}
