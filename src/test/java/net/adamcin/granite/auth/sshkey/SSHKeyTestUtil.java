package net.adamcin.granite.auth.sshkey;

import net.adamcin.commons.testing.junit.FailUtil;
import org.apache.commons.io.IOUtils;
import org.junit.Test;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.HashSet;
import java.util.Set;

import static org.junit.Assert.*;

/**
 *
 */
public class SSHKeyTestUtil {

    private static final File TEST_TEMP = new File("target/test-temp");
    static {
        TEST_TEMP.mkdirs();
    }
    public static final String B1024_PUBKEY = "AAAAB3NzaC1yc2EAAAADAQABAAAAgQC+Fz0pqK+XoCcukPhnPD+M1zb+FImbh5Lu3pkfW5DM67B6Hr9Q28LuWgNTfLqUn9o01W0TYzXDxtKG9psGuQ0wFJmqYJNbP6eRB3gimcr+C/eyy7N/evs8E36iMi7Si1piPd7QJ5l3D/tThI5cAACHYN0uqwphpXt4Lw2OZxIAQw==";
    public static final String B2048_PUBKEY = "AAAAB3NzaC1yc2EAAAADAQABAAABAQC/8kVdBX3dv6gtNl0YadNOcmoTsU+XQj9su9Q5EGiDNTQ9d7bqPW/Fckk4sa7QNB9lDls506iKdlSlh4AfFYrQaA3R0t+KLFtBw+ZGyhfUqin3RrIXotg9V1v/8leE/xy9tQNRLPT8YN0Qj0naguRmIp0del1gWwM4iyB5ZBA2ZITjOKNmzpDOL5UOs5TYNWP6ozMNbEdV515RvjiAlLz342O1dRGhT+0XUx5r2iq5D4CofGyl2BUTNzTJ/nLF5rETs6NTi8463HUC8JQ2a6d8HxO5LAh/1UBBvYR/38+LCnDpzDKl1j8FwAYpiRZuWMo+uMaI7ZjrJ6wDO4cicZ+R";
    public static final String B4096_PUBKEY = "AAAAB3NzaC1yc2EAAAADAQABAAACAQC4hXkVxytqXEAjTcu/deBpt0avLH4oxeMj+qvSwuzt4vGXQNQrqnQN1oCZr2y6y5yhXlpvG9j4wgd5SmfF4vSRYvi12ECJdLhh74zJY+9ztDWbkXglpo52RV8QWOj+LzrTqrf+qoSoKxaY5nN0iuRidLArkP3Jc2RZIHgurvLhe2okCk2Qwg275LcV5O71prsAisA30KGjiV+HgT+JctZ7WSX7sxyDPqqHKslpPBGFuXrpVqfsZYQRiGagw6+cAm/sQZzD4gwaHSi1C0sfQPHrQQVv2b5Zt8c47pIOcoKsqSRqfX6liA+yZsftwYkLoitqcWfrMNi5pqE0q1vjjlf41thZlJ/wlcpuQbJho8TCBOe3vHZQzcY2VrrzMI2wXOZLa4loAEJDs69WxJiBLqylhFIl+wZwklLQOaHGenMdKl4eBVaneZU0cPgmHBDWXFsr0KbQXgW8QXxJ3pswVa+FQ3QrKcwCveKOOhwclsSD4DRTwTV62dwOfh0o0G1UEtvJbTFo2NBLjTLL7jL1Fhgbx6yWgTK5p+XnQw5n4H3njSs5A3OLL4eAu81hULvf+UG7DyoDaLosHrfWlYFLb79mCLOubWGgWhqh8F/aMlPoSOLMXoaUsL5WYUkf7dn6hG7TlagxzSc5Rndbm09efiIv91IsaCKZlJyYUfjis96FZQ==";
    public static final String WITHPASS_PUBKEY = "AAAAB3NzaC1yc2EAAAADAQABAAABAQDwm2QdZogDqbOgG5KQgpQdDkb1iAIeH5Q3GOvr+LHtWWUxugdxk11yI28fO8WxAkg8gSTetJR9PQT0rvVIWZdjHpFhyLOiPpSz3+QkfPFilh7caPILfcLqivqmx4JMHXkMppn1u1n4ITbP/ZCaswX5S/zkEkGtBM/+3ckNlmxAEuaOJR1tXmdE9IiD6vPIIs9TeOYVkmpl17LTL82nKscOo1Wbof6MkuAeQutJJ6YFMWJSwx0kzAN5XSTrJvndArsCHayl4JTDNkkGj2wHMEh14MsMn+5/nbAN1xxpD4vfqG0k03dYFvk1EGhcWobBN6F/Pt7NWpZUaAdZ39wMTMH1";

    public InputStream getAuthorizedKeysStream() {
        return getClass().getResourceAsStream("/authorized_keys");
    }

    public static File getAuthorizedKeysFile() {
        return getResourceAsFile("/authorized_keys");
    }

    public static File getPrivateKeyAsFile(String parentName) {
        return getResourceAsFile("/" + parentName + "/id_rsa");
    }

    public static File getPublicKeyAsFile(String parentName) {
        return getResourceAsFile("/" + parentName + "/id_rsa.pub");
    }

    private static File getResourceAsFile(String name) {
        InputStream is = null;
        OutputStream os = null;
        try {
            is = SSHKeyTestUtil.class.getResourceAsStream(name);
            File temp = File.createTempFile("sshkeytest", ".tmp", TEST_TEMP);
            os = new FileOutputStream(temp);
            IOUtils.copy(is, os);
            return temp;
        } catch (IOException e) {
            FailUtil.sprintFail(e);
        } finally {
            IOUtils.closeQuietly(is);
            IOUtils.closeQuietly(os);
        }
        return null;
    }

    @Test
    public void testPopulateKeysSet() {
        Set<String> authKeys = new HashSet<String>();

        InputStream authKeysStream = null;
        try {
            authKeysStream = getAuthorizedKeysStream();
            SSHKeyUtil.populateKeysSet(authKeysStream, authKeys);
        } catch (IOException e) {
            FailUtil.sprintFail(e);
        } finally {
            if (authKeysStream != null) {
                try {
                    authKeysStream.close();
                } catch (IOException ignored) {}
            }
        }

        assertTrue("authKeys contains b1024 public key", authKeys.contains(B1024_PUBKEY));
        assertTrue("authKeys contains b2048 public key", authKeys.contains(B2048_PUBKEY));
        assertTrue("authKeys contains b4096 public key", authKeys.contains(B4096_PUBKEY));
        assertTrue("authKeys contains withpass public key", authKeys.contains(WITHPASS_PUBKEY));
    }


}
