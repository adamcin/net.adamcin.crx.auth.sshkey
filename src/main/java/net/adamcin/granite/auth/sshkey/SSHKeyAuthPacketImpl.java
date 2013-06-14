package net.adamcin.granite.auth.sshkey;

public final class SSHKeyAuthPacketImpl implements SSHKeyAuthPacket {

    private final String sessionId;
    private final String username;
    private final String format;
    private final String key;
    private final String signature;

    protected SSHKeyAuthPacketImpl(String sessionId, String username, String format, String key, String signature) {
        this.sessionId = sessionId;
        this.username = username;
        this.format = format;
        this.key = key;
        this.signature = signature;
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

    public String getSignature() {
        return signature;
    }

    @Override
    public String toString() {
        return sessionId + " " + username + " " + format + " " + key;
    }

    public static SSHKeyAuthPacketImpl parse(String packet) {
        String[] parts = packet.split(" ");

        if (parts.length != 5) {
            return null;
        }

        String sessionId = parts[0];
        String username = parts[1];
        String format = parts[2];
        String key = parts[3];
        String signature = parts[4];

        return new SSHKeyAuthPacketImpl(sessionId, username, format, key, signature);
    }
}
