package net.adamcin.granite.auth.sshkey;

import com.adobe.granite.crypto.CryptoException;
import com.adobe.granite.crypto.CryptoSupport;

import javax.servlet.http.HttpServletRequest;

public final class SSHKeySession {
    private String sessionId;
    private String username;
    private String fingerprint;
    private String realm;
    private String remoteAddr;
    private String serverName;
    private int serverPort;
    private long timestamp;

    private SSHKeySession(String sessionId, String username, String fingerprint, String realm, HttpServletRequest request, long timestamp) {
        this.sessionId = sessionId;
        this.username = username;
        this.fingerprint = fingerprint;
        this.realm = realm;
        this.remoteAddr = request.getRemoteAddr();
        this.serverName = request.getServerName();
        this.serverPort = request.getServerPort();
        this.timestamp = timestamp;
    }

    public String getSessionId() {
        if (sessionId == null) {
        }
        return sessionId;
    }

    public String getUsername() {
        return username;
    }

    public String getFingerprint() {
        return fingerprint;
    }

    public long getTimestamp() {
        return timestamp;
    }

    public boolean validateRequest(HttpServletRequest request, long maxAge) {
        return (System.currentTimeMillis() <= maxAge + this.timestamp) && this.remoteAddr.equals(request.getRemoteAddr())
                && this.serverName.equals(request.getServerName())
                && this.serverPort == request.getServerPort();
    }

    public static final SSHKeySession createSession(CryptoSupport cryptoSupport,
                                                    String username,
                                                    String fingerprint,
                                                    String realm,
                                                    HttpServletRequest request) throws
                                                                                                                                                                CryptoException {
        String remoteAddr = request.getRemoteAddr();
        String serverName = request.getServerName();
        int serverPort = request.getServerPort();
        Long timestamp = System.currentTimeMillis();
        String raw = new StringBuilder(username).append(fingerprint).append(realm)
                .append(remoteAddr).append(serverName).append(serverPort)
                .append(timestamp).toString();
        String encrypted = cryptoSupport.protect(raw);
        return new SSHKeySession(encrypted.substring(1, encrypted.length() - 1), username, fingerprint, realm, request, timestamp);
    }
}
