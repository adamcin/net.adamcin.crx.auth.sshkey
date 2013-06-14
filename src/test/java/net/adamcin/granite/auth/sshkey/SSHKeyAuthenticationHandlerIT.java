package net.adamcin.granite.auth.sshkey;


import net.adamcin.commons.testing.junit.TestBody;
import net.adamcin.commons.testing.sling.SlingITContext;
import net.adamcin.commons.testing.sling.VltpackITContext;
import org.apache.http.HttpResponse;
import org.apache.http.auth.AuthScheme;
import org.apache.http.auth.AuthSchemeFactory;
import org.apache.http.auth.AuthScope;
import org.apache.http.auth.UsernamePasswordCredentials;
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

public class SSHKeyAuthenticationHandlerIT {
    private static final Logger LOGGER = LoggerFactory.getLogger(SSHKeyAuthenticationHandlerIT.class);
    private SlingITContext context = new VltpackITContext();

    @Test
    public void testFail() {
        TestBody.test(new TestBody() {
            @Override protected void execute() throws Exception {
                File pkeyFile = SSHKeyTestUtil.getPrivateKeyAsFile("withpass");
                DefaultHttpClient client = (DefaultHttpClient) context.getHttpClient();
                client.getAuthSchemes().register("SSHKey", new AuthSchemeFactory() {
                    public AuthScheme newInstance(HttpParams params) {
                        LOGGER.error("[newInstance]");
                        return new SSHKeyAuthScheme(params);
                    }
                });

                client.getParams().setParameter(AuthPNames.TARGET_AUTH_PREF, Arrays.asList("sshkey"));
                client.getParams().setParameter(SSHKeyAuthScheme.HTTP_PARAM_SSHKEY_USERNAME, "admin");
                client.getParams().setParameter(SSHKeyAuthScheme.HTTP_PARAM_SSHKEY_IDENTITY, pkeyFile.getAbsolutePath());
                client.getParams().setParameter(SSHKeyAuthScheme.HTTP_PARAM_SSHKEY_PASSPHRASE, "dummydummy");
                HttpClientParams.setAuthenticating(client.getParams(), true);
                RequestCustomizer customizer = new RequestCustomizer() {
                    public void customizeRequest(Request r) {
                        r.getRequest().setHeader("X-Prefer-Authenticate", "SSHKey");
                    }
                };

                Request request = context.getRequestBuilder().buildGetRequest("/index.html").withCustomizer(customizer);

                HttpResponse response = context.getRequestExecutor().execute(request).assertStatus(200).getResponse();
            }
        });

    }
}
