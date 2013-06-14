package net.adamcin.granite.auth.sshkey;

public interface AuthorizationPacket {
    String getSessionId();
    String getSignature();
}
