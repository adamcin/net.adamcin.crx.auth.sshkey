package net.adamcin.granite.auth.sshkey;

import com.jcraft.jsch.HASH;
import com.jcraft.jsch.jce.MD5;

public final class FingerPrintUtil {
    private static String[] fingerPrintChars = {
            "0","1","2","3","4","5","6","7","8","9", "a","b","c","d","e","f"
    };

    /**
     * Essentially copied from {@link com.jcraft.jsch.Util#getFingerPrint(com.jcraft.jsch.HASH, byte[])}
     * @param keyBlob
     * @return
     */
    public static String getKeyFingerPrint(byte[] keyBlob) throws Exception {
        HASH hash = new MD5();
        hash.init();
        hash.update(keyBlob, 0, keyBlob.length);
        byte[] foo = hash.digest();
        StringBuffer sb = new StringBuffer();
        int bar;
        for(int i = 0; i < foo.length; i++){
            bar = foo[i]&0xff;
            sb.append(fingerPrintChars[(bar>>>4)&0xf]);
            sb.append(fingerPrintChars[(bar)&0xf]);
            if(i + 1 < foo.length) {
                sb.append(":");
            }
        }
        return sb.toString();
    }

    private FingerPrintUtil() {
    }
}
