package net.adamcin.granite.auth.sshkey;

public final class AuthorizationPacketImpl implements AuthorizationPacket {

    private final String sessionId;
    private final String signature;

    public AuthorizationPacketImpl(String sessionId, String signature) {
        this.sessionId = sessionId;
        this.signature = signature;
    }

    public String getSessionId() {
        return sessionId;
    }

    public String getSignature() {
        return signature;
    }

    @Override
    public String toString() {
        return sessionId;
    }

    public static AuthorizationPacketImpl parse(String packet) {
        String[] parts = packet.split(" ");

        if (parts.length != 2) {
            return null;
        }

        String sessionId = parts[0];
        String signature = parts[1];

        return new AuthorizationPacketImpl(sessionId, signature);
    }
}
