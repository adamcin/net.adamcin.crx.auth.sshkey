package net.adamcin.granite.auth.sshkey;

public final class MockAuthorizationPacket implements AuthorizationPacket {

    private String sessionId;
    private String signature;

    public MockAuthorizationPacket(String sessionId) {
        this.sessionId = sessionId;
    }

    public String getSessionId() {
        return sessionId;
    }

    public void setSignature(String signature) {
        this.signature = signature;
    }

    public String getSignature() {
        return signature;
    }

    @Override
    public String toString() {
        return sessionId;
    }

}
