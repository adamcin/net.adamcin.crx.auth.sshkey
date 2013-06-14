package net.adamcin.granite.auth.sshkey;

import com.adobe.granite.crypto.CryptoException;
import com.adobe.granite.crypto.CryptoSupport;
import com.day.crx.security.token.TokenCookie;
import com.day.crx.security.token.TokenUtil;
import org.apache.felix.scr.annotations.Activate;
import org.apache.felix.scr.annotations.Component;
import org.apache.felix.scr.annotations.Deactivate;
import org.apache.felix.scr.annotations.Property;
import org.apache.felix.scr.annotations.Reference;
import org.apache.felix.scr.annotations.Service;
import org.apache.sling.auth.core.spi.AbstractAuthenticationHandler;
import org.apache.sling.auth.core.spi.AuthenticationInfo;
import org.apache.sling.commons.osgi.PropertiesUtil;
import org.apache.sling.jcr.api.SlingRepository;
import org.apache.sling.settings.SlingSettingsService;
import org.osgi.service.component.ComponentContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.jcr.RepositoryException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Component(label = "SSH Key Authentication Handler", metatype = true)
@Service
public final class SSHKeyAuthenticationHandler extends AbstractAuthenticationHandler {
    private static final Logger LOGGER = LoggerFactory.getLogger(SSHKeyAuthenticationHandler.class);

    private static final String HEADER_AUTHENTICATE = "WWW-Authenticate";
    private static final String HEADER_AUTHORIZATION = "Authorization";
    private static final String AUTHORIZED_KEYS_REL_PATH = ".ssh/authorized_keys";
    public static final String X_SSHKEY_USERNAME_HEADER = "X-SSHKey-Username";
    public static final String X_SSHKEY_FINGERPRINT_HEADER = "X-SSHKey-Fingerprint";
    private static final int MAX_SESSIONS = 10000;

    @Property(name = TYPE_PROPERTY, propertyPrivate = true)
    private static final String AUTH_TYPE = "SSHKey";

    @Property(name = PATH_PROPERTY, label = "Path")
    private static final String AUTH_PATH = "/";

    @Property(name = "service.ranking", label = "Service Ranking")
    private static final String SERVICE_RANKING = "10000";

    @Property(label = "Authorized Keys File", description = "Path to authorized_keys file. Leave empty to expect ${sling.home}../.ssh/authorized_keys or ${user.home}/.ssh/authorized_keys.", value = "")
    private static final String OSGI_AUTH_KEYS_PATH = "auth.sshkey.authorized_keys";

    private static final String DEFAULT_REALM = "Day Communique 5";
    @Property(label = "Realm", description = "Authentication Realm", value = DEFAULT_REALM)
    private static final String OSGI_REALM = "auth.sshkey.realm";

    @Reference
    private SlingSettingsService slingSettingsService;

    @Reference
    private SlingRepository repository;

    @Reference
    private CryptoSupport cryptoSupport;

    private boolean disabled;
    private String authorizedKeysPath;
    private String realm;

    private final Map<String, SSHPublicKey> authorizedKeys = Collections.synchronizedMap(
            new HashMap<String, SSHPublicKey>()
    );
    private final Map<String, SSHKeySession> sessions = Collections.synchronizedMap(new HashMap<String, SSHKeySession>());

    @Activate
    protected void activate(ComponentContext ctx, Map<String, Object> props) {
        this.authorizedKeysPath = PropertiesUtil.toString(props.get(OSGI_AUTH_KEYS_PATH), "");
        File authorizedKeysFile = getAuthorizedKeysFile();
        if (authorizedKeysFile != null) {
            synchronized (authorizedKeys) {
                InputStream authKeysStream = null;
                try {
                    authKeysStream = new FileInputStream(authorizedKeysFile);
                    List<SSHPublicKey> keys = SSHPublicKey.readKeys(new InputStreamReader(authKeysStream));
                    for (SSHPublicKey key : keys) {
                        authorizedKeys.put(key.getFingerPrint(), key);
                    }
                } catch (IOException e) {
                    LOGGER.error("[activate] failed to read authorized_keys file: {}, exception: {}",
                                 authorizedKeysFile, e.getMessage());
                } finally {
                    if (authKeysStream != null) {
                        try {
                            authKeysStream.close();
                        } catch (IOException ignored) {}
                    }
                }
            }
        }

        this.realm = PropertiesUtil.toString(props.get(OSGI_REALM), DEFAULT_REALM);
    }

    @Deactivate
    protected void deactivate(ComponentContext ctx) {
        this.authorizedKeysPath = null;
        this.realm = null;
        synchronized (authorizedKeys) {
            authorizedKeys.clear();
        }
        synchronized (sessions) {
            sessions.clear();
        }
    }

    protected boolean isAllowedToLogin(HttpServletRequest request) {
        return true;
    }

    protected File getAuthorizedKeysFile() {
        if (authorizedKeysPath != null && authorizedKeysPath.trim().length() > 0) {
            File configOverride = new File(authorizedKeysPath);
            if (configOverride.exists() && configOverride.canRead()) {
                return configOverride;
            } else {
                return null;
            }
        }

        File appOverride = new File(slingSettingsService.getSlingHomePath(),
                                    ".." + File.separator + AUTHORIZED_KEYS_REL_PATH);

        if (appOverride.exists() && appOverride.canRead()) {
            return appOverride;
        } else {
            File userFile = new File(System.getProperty("user.home"), AUTHORIZED_KEYS_REL_PATH);
            if (userFile.exists() && userFile.canRead()) {
                return userFile;
            } else {
                return null;
            }
        }
    }

    /**
     *
     * @param request
     * @param response
     * @return
     */
    public AuthenticationInfo extractCredentials(HttpServletRequest request,
                                                 HttpServletResponse response) {

        if (isDisabled() || !isAllowedToLogin(request) ) {
            return null;
        }

        AuthenticationInfo info = handleLogin(request, response);
        if (info != null) {
            return info;
        }

        if (forceAuthentication(request, response)) {
            return AuthenticationInfo.DOING_AUTH;
        }

        return null;
    }

    protected static String getSSHKeyUsername(HttpServletRequest request) {
        return request.getHeader(X_SSHKEY_USERNAME_HEADER);
    }

    protected boolean forceAuthentication(HttpServletRequest request,
                                          HttpServletResponse response) {

        boolean authenticationForced = false;
        String username = getSSHKeyUsername(request);
        if (username != null) {
            if (!response.isCommitted()) {
                authenticationForced = sendUnauthorized(username, request, response);
            }
        }

        return authenticationForced;
    }

    protected String selectFingerprint(String username, HttpServletRequest request) {
        Enumeration fingerprints = request.getHeaders(X_SSHKEY_FINGERPRINT_HEADER);
        if (fingerprints != null) {
            while (fingerprints.hasMoreElements()) {
                String fingerprint = (String) fingerprints.nextElement();
                if (authorizedKeys.containsKey(fingerprint)) {
                    return fingerprint;
                }
            }
        }
        return null;
    }

    protected boolean sendUnauthorized(String username, HttpServletRequest request,
                                          HttpServletResponse response) {
        if (response.isCommitted()) {
            return false;
        }

        String fingerprint = selectFingerprint(username, request);
        SSHKeySession session = createSession(username, fingerprint, request);

        if (session != null) {
            response.reset();
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);

            String headerValue = String.format("%s realm=\"%s\", fingerprint=\"%s\", sessionId=\"%s\"",
                                               AUTH_TYPE, this.realm, fingerprint, session.getSessionId());

            response.setHeader(HEADER_AUTHENTICATE, headerValue);
            try {
                response.flushBuffer();
                return true;
            } catch (IOException e) {
                LOGGER.error("Failed to send WWW-Authenticate header", e);
            }
        }

        return false;
    }

    protected SSHKeySession createSession(String username, String fingerprint, HttpServletRequest request) {
        if (sessions.size() < MAX_SESSIONS) {
            try {
                SSHKeySession session = SSHKeySession.createSession(cryptoSupport, username, fingerprint, realm, request);
                synchronized (this.sessions) {
                    this.sessions.put(session.getSessionId(), session);
                }
                return session;
            } catch (CryptoException e) {
                LOGGER.error("[createSession] failed to encrypt session");
            }
        }
        return null;
    }

    protected SSHKeySession validateSession(HttpServletRequest request, String sessionId) {
        if (this.sessions.containsKey(sessionId)) {
            synchronized (this.sessions) {
                SSHKeySession session = this.sessions.remove(sessionId);
                if (session != null && session.validateRequest(request, 60L * 1000L)) {
                    return session;
                }
            }
        }

        return null;
    }

    public boolean requestCredentials(HttpServletRequest request, HttpServletResponse response)
            throws IOException {

        return !isDisabled() && isAllowedToLogin(request) && forceAuthentication(request, response);
    }

    public void dropCredentials(HttpServletRequest request, HttpServletResponse response)
            throws IOException {
        // do nothing
    }

    public boolean isDisabled() {
        return disabled || authorizedKeys.isEmpty();
    }

    public AuthenticationInfo handleLogin(HttpServletRequest request,
                                                 HttpServletResponse response) {

        // Return immediately if the header is missing
        String authHeader = request.getHeader(HEADER_AUTHORIZATION);
        if (authHeader == null || authHeader.length() == 0) {
            return null;
        }

        int blank = authHeader.indexOf(' ');
        if (blank <= 0) {
            return null;
        }

        String authType = authHeader.substring(0, blank);
        String authInfo = authHeader.substring(blank).trim();

        if (!AUTH_TYPE.equals(authType)) {
            return null;
        }

        AuthenticationInfo info = null;

        AuthorizationPacketImpl packet = AuthorizationPacketImpl.parse(authInfo);

        SSHKeySession session = validateSession(request, packet.getSessionId());

        SSHPublicKey publicKey = this.authorizedKeys.get(session.getFingerprint());

        boolean signatureValid = publicKey != null && publicKey.verify(packet);

        if (signatureValid) {
            try {
                if (request.getAttribute(TokenCookie.class.getName()) != null) {
                    request.setAttribute(TokenCookie.class.getName(), null);
                }
                info = TokenUtil.createCredentials(request, response, repository, session.getUsername(), false);
            } catch (RepositoryException e) {
                LOGGER.error("[handleLogin] failed to create token", e);
            }
        }

        if (info == null) {
            info = AuthenticationInfo.FAIL_AUTH;
        }

        return info;
    }

}
