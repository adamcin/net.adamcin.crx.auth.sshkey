package net.adamcin.granite.auth.sshkey;

import com.jcraft.jsch.Identity;
import com.jcraft.jsch.JSch;
import org.apache.commons.codec.binary.Base64;
import org.apache.http.Header;
import org.apache.http.HttpRequest;
import org.apache.http.auth.AuthenticationException;
import org.apache.http.auth.Credentials;
import org.apache.http.auth.MalformedChallengeException;
import org.apache.http.impl.auth.AuthSchemeBase;
import org.apache.http.message.BasicHeader;
import org.apache.http.params.HttpParams;
import org.apache.http.util.CharArrayBuffer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.HashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class SSHKeyAuthScheme extends AuthSchemeBase {
    private static final Logger LOGGER = LoggerFactory.getLogger(SSHKeyAuthScheme.class);
    private static final Pattern REALM_PATTERN = Pattern.compile("realm=\"([^\"]*)\"");
    private static final Pattern FINGERPRINT_PATTERN = Pattern.compile("fingerprint=\"([^\"]*)\"");
    private static final Pattern SESSIONID_PATTERN = Pattern.compile("sessionId=\"([^\"\\s]*)\"");

    public static final String HTTP_PARAM_SSHKEY_IDENTITITES = "sshkey.identities";
    public static final String CHALLENGE_PARAM_FINGERPRINT = "fingerprint";
    public static final String CHALLENGE_PARAM_SESSION_ID = "sessionId";

    private String realm;
    private Map<String, String> params = new HashMap<String, String>();
    private JSch jSch;
    // Fingerprint, Identity
    private Map<String, Identity> identities;

    public SSHKeyAuthScheme(HttpParams httpParams, Map<String, Identity> identities) {
        this.jSch = new JSch();
        this.identities = identities;
    }

    @Override
    protected void parseChallenge(CharArrayBuffer buffer, int beginIndex, int endIndex)
            throws MalformedChallengeException {

        String challenge = buffer.substring(beginIndex, endIndex);
        LOGGER.error("[parseChallenge] challenge: {}", challenge);

        Matcher realmMatcher = REALM_PATTERN.matcher(challenge);
        Matcher fingerprintMatcher = FINGERPRINT_PATTERN.matcher(challenge);
        Matcher sessionIdMatcher = SESSIONID_PATTERN.matcher(challenge);
        if (realmMatcher.find() && fingerprintMatcher.find() && sessionIdMatcher.find()) {
            this.realm = realmMatcher.group(1);
            String fingerprint = fingerprintMatcher.group(1);
            params.put(CHALLENGE_PARAM_FINGERPRINT, fingerprint);
            String sessionId = sessionIdMatcher.group(1);
            params.put(CHALLENGE_PARAM_SESSION_ID, sessionId);
        } else {
            throw new MalformedChallengeException("Challenge must include realm and sessionId");
        }
    }

    public String getSchemeName() {
        return "SSHKey";
    }

    public String getParameter(String name) {
        return this.params.get(name);
    }

    public String getRealm() {
        return this.realm;
    }

    public boolean isConnectionBased() {
        return false;
    }

    public boolean isComplete() {
        return true;
    }

    public Header authenticate(Credentials credentials, HttpRequest request) throws AuthenticationException {
        Identity identity = this.identities.get(this.getParameter(CHALLENGE_PARAM_FINGERPRINT));

        if (identity != null) {
            String sessionId = this.getParameter(CHALLENGE_PARAM_SESSION_ID);

            String signature = Base64.encodeBase64URLSafeString(identity.getSignature(sessionId.getBytes()));
            String headerValue = "SSHKey " + sessionId + " " + signature;
            return new BasicHeader("Authorization", headerValue);
        } else {
            return null;
        }
    }
}
