package net.adamcin.granite.auth.sshkey;

import com.day.crx.security.token.TokenUtil;
import org.apache.commons.codec.binary.Base64;
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
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

@Component(label = "SSH Key Authentication Handler", metatype = true)
@Service
public final class SSHKeyAuthenticationHandler extends AbstractAuthenticationHandler {
    private static final Logger LOGGER = LoggerFactory.getLogger(SSHKeyAuthenticationHandler.class);

    private static final String HEADER_AUTHENTICATE = "WWW-Authenticate";
    private static final String HEADER_AUTHORIZATION = "Authorization";
    private static final String AUTHORIZED_KEYS_REL_PATH = ".ssh/authorized_keys";
    private static final String REQUEST_LOGIN_PARAMETER = "sling:authRequestLogin";
    private static final String X_PREFER_AUTHENTICATE_HEADER = "X-Prefer-Authenticate";
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

    private boolean disabled;
    private String authorizedKeysPath;
    private String realm;

    private final Set<SSHPublicKey> authorizedKeys = Collections.synchronizedSet(new HashSet<SSHPublicKey>());
    private final Map<String, Long> sessions = Collections.synchronizedMap(new HashMap<String, Long>());

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
                    authorizedKeys.addAll(keys);
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

        if (isDisabled() || !isAllowedToLogin(request)) {
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

    protected static boolean sshKeyAuthPreferred(HttpServletRequest request) {
        String preferHeader = request.getHeader(X_PREFER_AUTHENTICATE_HEADER);
        return preferHeader != null && preferHeader.toLowerCase().contains(AUTH_TYPE.toLowerCase());
    }

    protected boolean forceAuthentication(HttpServletRequest request,
                                          HttpServletResponse response) {

        boolean authenticationForced = false;
        if (request.getParameter(REQUEST_LOGIN_PARAMETER) != null || sshKeyAuthPreferred(request)) {
            if (!response.isCommitted()) {
                authenticationForced = sendUnauthorized(request, response);
            }
        }

        return authenticationForced;
    }

    protected boolean sendUnauthorized(HttpServletRequest request,
                                          HttpServletResponse response) {
        if (response.isCommitted()) {
            return false;
        }

        String sessionId = createSessionId(request);

        if (sessionId != null) {
            response.reset();
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.setHeader(HEADER_AUTHENTICATE, AUTH_TYPE + " realm=\"" + this.realm + "\"" + ", sessionId=\"" + sessionId + "\"");
            try {
                response.flushBuffer();
                return true;
            } catch (IOException e) {
                LOGGER.error("Failed to send WWW-Authenticate header", e);
            }
        }

        return false;
    }

    protected String createSessionId(HttpServletRequest request) {
        if (sessions.size() < MAX_SESSIONS) {
            Long timestamp = System.currentTimeMillis();
            String constructed = String.valueOf(timestamp) + " " + constructBaseSessionId(request);
            String sessionId = Base64.encodeBase64URLSafeString(constructed.getBytes());
            synchronized (this.sessions) {
                this.sessions.put(sessionId, timestamp);
            }
            return sessionId;
        }
        return null;
    }

    protected String constructBaseSessionId(HttpServletRequest request) {
        StringBuilder builder = new StringBuilder();
        builder.append(request.getRemoteAddr()).append(",")
                .append(request.getServerName()).append(":")
                .append(request.getServerPort()).append("|")
                .append(this.realm);
        return builder.toString();

    }

    protected boolean validateSessionId(HttpServletRequest request, String sessionId) {
        String base = constructBaseSessionId(request);
        String sessionIdDecoded = new String(Base64.decodeBase64(sessionId));
        int firstSpace = sessionIdDecoded.indexOf(' ');
        if (firstSpace > 0 && sessionIdDecoded.substring(firstSpace + 1).equals(base)) {
            synchronized (this.sessions) {
                Long timestamp = this.sessions.remove(sessionId);
                if (timestamp != null && System.currentTimeMillis() - timestamp < 60L * 1000L) {
                    return true;
                }
            }
        }

        return false;
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

    /**
     *
     * @param request
     * @param response
     * @return
     */
    public AuthenticationInfo handleSecretRequest(HttpServletRequest request,
                                                 HttpServletResponse response) {



        return AuthenticationInfo.DOING_AUTH;
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

        SSHKeyAuthPacketImpl packet = SSHKeyAuthPacketImpl.parse(authInfo);

        SSHPublicKey publicKey = SSHPublicKey.createKey(packet.getFormat(), packet.getKey());
        boolean keyAuthorized = authorizedKeys.contains(publicKey);
        boolean sessionIdValid = validateSessionId(request, packet.getSessionId());
        boolean signatureValid = SSHPublicKey.verify(packet);

        if (keyAuthorized && sessionIdValid && signatureValid) {
            try {
                info = TokenUtil.createCredentials(request, response, repository, packet.getUsername(), false);
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
