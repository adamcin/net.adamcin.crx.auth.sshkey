package net.adamcin.granite.auth.sshkey;


import com.jcraft.jsch.Identity;
import com.jcraft.jsch.JSch;
import com.jcraft.jsch.JSchException;
import net.adamcin.commons.testing.junit.FailUtil;
import net.adamcin.commons.testing.junit.TestBody;
import net.adamcin.commons.testing.sling.SlingITContext;
import net.adamcin.commons.testing.sling.VltpackITContext;
import org.apache.http.HttpResponse;
import org.apache.http.auth.AuthScheme;
import org.apache.http.auth.AuthSchemeFactory;
import org.apache.http.auth.params.AuthPNames;
import org.apache.http.client.params.HttpClientParams;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.params.HttpParams;
import org.apache.sling.testing.tools.http.Request;
import org.apache.sling.testing.tools.http.RequestCustomizer;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Vector;

public class SSHKeyAuthenticationHandlerIT {
    private static final Logger LOGGER = LoggerFactory.getLogger(SSHKeyAuthenticationHandlerIT.class);
    private SlingITContext context = new VltpackITContext();

    @Test
    public void testFail() {
        TestBody.test(new TestBody() {
            @Override protected void execute() throws Exception {

                JSch jSch = new JSch();

                File pkeyFile = SSHKeyTestUtil.getPrivateKeyAsFile("withpass");
                try {
                    jSch.addIdentity(pkeyFile.getAbsolutePath(), "dummydummy");
                } catch (JSchException e) {
                    FailUtil.sprintFail(e);
                }

                final Map<String, Identity> identities = new HashMap<String, Identity>();

                Vector _identities = jSch.getIdentityRepository().getIdentities();
                if (_identities != null) {
                    for (Object obj : _identities) {
                        Identity ident = (Identity) obj;
                        try {
                            String fingerprint = FingerPrintUtil.getKeyFingerPrint(ident.getPublicKeyBlob());
                            identities.put(fingerprint, ident);
                        } catch (Exception e) {
                            LOGGER.error("[reloadIdentities] failed to construct fingerprint for identity: " + ident.getName(), e);
                        }
                    }
                }

                DefaultHttpClient client = (DefaultHttpClient) context.getHttpClient();
                client.getAuthSchemes().register("SSHKey", new AuthSchemeFactory() {
                    public AuthScheme newInstance(HttpParams params) {
                        LOGGER.error("[newInstance]");
                        return new SSHKeyAuthScheme(params, identities);
                    }
                });

                client.getParams().setParameter(AuthPNames.TARGET_AUTH_PREF, Arrays.asList("sshkey"));
                client.getParams().setParameter(SSHKeyAuthScheme.HTTP_PARAM_SSHKEY_IDENTITITES,
                                                Collections.unmodifiableMap(identities));
                HttpClientParams.setAuthenticating(client.getParams(), true);
                RequestCustomizer customizer = new RequestCustomizer() {

                    public void customizeRequest(Request r) {
                        r.getRequest().setHeader(SSHKeyAuthenticationHandler.X_SSHKEY_USERNAME_HEADER, "admin");
                        for (String fingerprint : identities.keySet()) {
                            r.getRequest().addHeader(SSHKeyAuthenticationHandler.X_SSHKEY_FINGERPRINT_HEADER, fingerprint);
                        }
                    }
                };

                Request request = context.getRequestBuilder().buildGetRequest("/index.html").withCustomizer(customizer);

                HttpResponse response = context.getRequestExecutor().execute(request).assertStatus(200).getResponse();
            }
        });

    }
}
