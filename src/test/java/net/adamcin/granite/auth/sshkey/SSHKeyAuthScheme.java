package net.adamcin.granite.auth.sshkey;

import com.jcraft.jsch.Identity;
import com.jcraft.jsch.JSch;
import com.jcraft.jsch.JSchException;
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

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Vector;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Created with IntelliJ IDEA.
 * User: madamcin
 * Date: 6/13/13
 * Time: 12:52 PM
 * To change this template use File | Settings | File Templates.
 */
public class SSHKeyAuthScheme extends AuthSchemeBase {
    private static final Logger LOGGER = LoggerFactory.getLogger(SSHKeyAuthScheme.class);
    private static final Pattern REALM_PATTERN = Pattern.compile("realm=\"([^\"]*)\"");
    private static final Pattern SESSIONID_PATTERN = Pattern.compile("sessionId=\"([^\"\\s]*)\"");

    public static final String HTTP_PARAM_SSHKEY_USERNAME = "sshkey.username";
    public static final String HTTP_PARAM_SSHKEY_IDENTITY = "sshkey.identity";
    public static final String HTTP_PARAM_SSHKEY_PASSPHRASE = "sshkey.passphrase";
    public static final String PARAM_SESSION_ID = "sessionId";

    private String realm;
    private Map<String, String> params = new HashMap<String, String>();
    private JSch jSch;
    private String username;
    private String identity;
    private String passphrase;
    private List<Identity> identities = new ArrayList<Identity>();

    public SSHKeyAuthScheme(HttpParams httpParams) {
        this.jSch = new JSch();
        this.username = (String) httpParams.getParameter(HTTP_PARAM_SSHKEY_USERNAME);
        this.identity = (String) httpParams.getParameter(HTTP_PARAM_SSHKEY_IDENTITY);
        this.passphrase = (String) httpParams.getParameter(HTTP_PARAM_SSHKEY_PASSPHRASE);
    }

    protected void reloadIdentities() {
        this.identities.clear();

        if (identity != null) {
            try {
                if (this.passphrase != null) {
                    this.jSch.addIdentity(identity, this.passphrase);
                } else {
                    this.jSch.addIdentity(identity);
                }
            } catch (JSchException e) {
                System.err.println("Failed to add identity: " + identity + ". Reason: " + e.getMessage());
            }
        }

        Vector _identities = this.jSch.getIdentityRepository().getIdentities();
        for (Object obj : _identities) {
            Identity ident = (Identity) obj;
            this.identities.add(ident);
        }
    }

    @Override
    protected void parseChallenge(CharArrayBuffer buffer, int beginIndex, int endIndex)
            throws MalformedChallengeException {

        String challenge = buffer.substring(beginIndex, endIndex);

        Matcher realmMatcher = REALM_PATTERN.matcher(challenge);
        Matcher sessionIdMatcher = SESSIONID_PATTERN.matcher(challenge);
        if (realmMatcher.find() && sessionIdMatcher.find()) {
            this.realm = realmMatcher.group(1);
            String sessionId = sessionIdMatcher.group(1);
            params.put(PARAM_SESSION_ID, sessionId);
            this.reloadIdentities();
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
        return identities.isEmpty();
    }

    public Header authenticate(Credentials credentials, HttpRequest request) throws AuthenticationException {
        String loginAs = this.username;
        if (loginAs == null) {
            loginAs = credentials != null ? credentials.getUserPrincipal().getName() : "admin";
        }

        if (!this.identities.isEmpty()) {
            Identity identity = this.identities.remove(0);
            String pubKeyBlob = Base64.encodeBase64URLSafeString(identity.getPublicKeyBlob());
            String payload = this.getParameter(PARAM_SESSION_ID) + " " + loginAs + " " + identity.getAlgName() + " " + pubKeyBlob;

            String signature = Base64.encodeBase64URLSafeString(identity.getSignature(payload.getBytes()));
            String headerValue = "SSHKey " + payload + " " + signature;
            return new BasicHeader("Authorization", headerValue);
        } else {
            return null;
        }
    }
}
