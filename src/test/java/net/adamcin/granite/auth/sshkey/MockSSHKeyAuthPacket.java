package net.adamcin.granite.auth.sshkey;

public final class MockSSHKeyAuthPacket implements SSHKeyAuthPacket {

    private String sessionId;
    private String username;
    private String format;
    private String key;
    private String signature;

    public MockSSHKeyAuthPacket(String sessionId, String username, String format, String key) {
        this.sessionId = sessionId;
        this.username = username;
        this.format = format;
        this.key = key;
    }

    public String getSessionId() {
        return sessionId;
    }

    public String getUsername() {
        return username;
    }

    public String getFormat() {
        return format;
    }

    public String getKey() {
        return key;
    }

    public void setSignature(String signature) {
        this.signature = signature;
    }

    public String getSignature() {
        return signature;
    }

    @Override
    public String toString() {
        return sessionId + " " + username + " " + format + " " + key;
    }

}
