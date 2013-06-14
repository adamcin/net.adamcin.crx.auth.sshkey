package net.adamcin.granite.auth.sshkey;

public interface SSHKeyAuthPacket {
    String getSessionId();
    String getUsername();
    String getFormat();
    String getKey();
    String getSignature();
}
