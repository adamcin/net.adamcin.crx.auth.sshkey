package net.adamcin.granite.auth.sshkey;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Created with IntelliJ IDEA.
 * User: madamcin
 * Date: 6/7/13
 * Time: 2:17 PM
 * To change this template use File | Settings | File Templates.
 */
public class SSHKeyUtil {
    public static final String PEM_PUBLIC_PREFIX = "-----BEGIN SSH2 PUBLIC KEY-----";
    public static final String PEM_PUBLIC_SUFFIX = "-----END SSH2 PUBLIC KEY-----";
    public static final String PEM_PRIVATE_PREFIX = "-----BEGIN RSA PRIVATE KEY-----";
    public static final String PEM_PRIVATE_SUFFIX = "-----END RSA PRIVATE KEY-----";

    /**
     * AUTHORIZED_KEYS FILE FORMAT
     *      AuthorizedKeysFile specifies the file containing public keys for public
     *      key authentication; if none is specified, the default is
     *      ~/.ssh/authorized_keys.  Each line of the file contains one key (empty
     *      (because of the size of the public key encoding) up to a limit of 8 kilo-
     *      bytes, which permits DSA keys up to 8 kilobits and RSA keys up to 16
     *      kilobits.  You don't want to type them in; instead, copy the
     *      identity.pub, id_dsa.pub, or the id_rsa.pub file and edit it.
     *
     *      sshd enforces a minimum RSA key modulus size for protocol 1 and protocol
     *      2 keys of 768 bits.
     *
     *      The options (if present) consist of comma-separated option specifica-
     *      tions.  No spaces are permitted, except within double quotes.  The fol-
     *      lowing option specifications are supported (note that option keywords are
     *      case-insensitive):
     *
     *      command="command"
     *              Specifies that the command is executed whenever this key is used
     *              for authentication.  The command supplied by the user (if any) is
     *              ignored.  The command is run on a pty if the client requests a
     *              pty; otherwise it is run without a tty.  If an 8-bit clean chan-
     *              nel is required, one must not request a pty or should specify
     *              no-pty.  A quote may be included in the command by quoting it
     *              with a backslash.  This option might be useful to restrict cer-
     *              tain public keys to perform just a specific operation.  An exam-
     *              ple might be a key that permits remote backups but nothing else.
     *              Note that the client may specify TCP and/or X11 forwarding unless
     *              they are explicitly prohibited.  The command originally supplied
     *              by the client is available in the SSH_ORIGINAL_COMMAND environ-
     *              ment variable.  Note that this option applies to shell, command
     *              or subsystem execution.
     *
     *      environment="NAME=value"
     *              Specifies that the string is to be added to the environment when
     *              logging in using this key.  Environment variables set this way
     *              override other default environment values.  Multiple options of
     *              this type are permitted.  Environment processing is disabled by
     *              default and is controlled via the PermitUserEnvironment option.
     *              This option is automatically disabled if UseLogin is enabled.
     *
     *      from="pattern-list"
     *              Specifies that in addition to public key authentication, either
     *              the canonical name of the remote host or its IP address must be
     *              present in the comma-separated list of patterns.  See PATTERNS in
     *              ssh_config(5) for more information on patterns.
     *
     *              In addition to the wildcard matching that may be applied to host-
     *              names or addresses, a from stanza may match IP addresses using
     *              CIDR address/masklen notation.
     *
     *              The purpose of this option is to optionally increase security:
     *              public key authentication by itself does not trust the network or
     *              name servers or anything (but the key); however, if somebody
     *              somehow steals the key, the key permits an intruder to log in
     *              from anywhere in the world.  This additional option makes using a
     *              stolen key more difficult (name servers and/or routers would have
     *              to be compromised in addition to just the key).
     *
     *      no-user-rc
     *              Disables execution of ~/.ssh/rc.
     *
     *      no-X11-forwarding
     *              Forbids X11 forwarding when this key is used for authentication.
     *              Any X11 forward requests by the client will return an error.
     *
     *      permitopen="host:port"
     *              Limit local ``ssh -L'' port forwarding such that it may only con-
     *              nect to the specified host and port.  IPv6 addresses can be spec-
     *              ified with an alternative syntax: host/port.  Multiple permitopen
     *              options may be applied separated by commas.  No pattern matching
     *              is performed on the specified hostnames, they must be literal
     *              domains or addresses.
     *
     *      tunnel="n"
     *              Force a tun(4) device on the server.  Without this option, the
     *              next available device will be used if the client requests a tun-
     *              nel.
     *
     *      An example authorized_keys file:
     *
     *         # Comments allowed at start of line
     *         ssh-rsa AAAAB3Nza...LiPk== user@example.net
     *         from="*.sales.example.net,!pc.sales.example.net" ssh-rsa
     *         AAAAB2...19Q== john@example.net
     *         command="dump /home",no-pty,no-port-forwarding ssh-dss
     *         AAAAC3...51R== example.net
     *         permitopen="192.0.2.1:80",permitopen="192.0.2.2:25" ssh-dss
     *         AAAAB5...21S==
     *         tunnel="0",command="sh /etc/netstart tun0" ssh-rsa AAAA...==
     *         jane@example.net
     * @param authorizedKeys
     * @param keysSet
     */
    public static void populateKeysSet(InputStream authorizedKeys, Set<String> keysSet) throws IOException {
        Pattern keyPattern = Pattern.compile("^([^\\s]+)\\s+([^\\s]+)(\\s|$)");
        BufferedReader reader = new BufferedReader(new InputStreamReader(authorizedKeys));

        String line;
        while ((line = reader.readLine()) != null) {
            Matcher matcher = keyPattern.matcher(line);
            if (matcher.find()) {
                String key = matcher.group(2);
                keysSet.add(key);
            }
        }
    }

    public static String expandToPEM(String publicKey) {
        final int lineLength = 77;
        StringBuilder builder = new StringBuilder(PEM_PUBLIC_PREFIX);
        if (publicKey != null) {
            String _keyBuf = publicKey;
            while (_keyBuf.length() > 0) {
                if (_keyBuf.length() > lineLength) {
                    builder.append("\n").append(_keyBuf.substring(0, lineLength - 1));
                    _keyBuf = _keyBuf.substring(lineLength);
                } else {
                    builder.append("\n").append(_keyBuf);
                    _keyBuf = "";
                }
            }
        }
        builder.append("\n" + PEM_PUBLIC_SUFFIX + "\n");

        return builder.toString();
    }
}
