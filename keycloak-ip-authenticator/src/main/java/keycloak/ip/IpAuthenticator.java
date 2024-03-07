package keycloak.ip;

import jakarta.ws.rs.core.Response;
import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

public class IpAuthenticator implements Authenticator {

    private static final Logger logger = Logger.getLogger(IpAuthenticator.class);
    @Override
    public void authenticate(AuthenticationFlowContext context) {
        RealmModel realm = context.getRealm();
        UserModel user = context.getUser();

        String remoteIPAddress = context.getConnection().getRemoteAddr();
        String allowedIPAddress = getAllowedIPAddress(context);
        logger.info("remoteIPAddress = " + remoteIPAddress);

        if (!allowedIPAddress.equals(remoteIPAddress)) {
            logger.infof("IPs do not match. Realm %s expected %s but user %s logged from %s", realm.getName(), allowedIPAddress, user.getUsername(), remoteIPAddress);
            Response challengeResponse = context.form().setError("Access is forbidden for your IP: " + remoteIPAddress)
                    .createErrorPage(Response.Status.FORBIDDEN);
            context.failure(AuthenticationFlowError.GENERIC_AUTHENTICATION_ERROR,challengeResponse);
        } else {
            context.success();
        }
    }

    private String getAllowedIPAddress(AuthenticationFlowContext context) {
        //TODO
        return IpAuthenticatorFactory.ALLOWED_IP_ADDRESS_CONFIG;
        /*AuthenticatorConfigModel configModel = context.getAuthenticatorConfig();
        Map<String, String> config = configModel.getConfig();
        return config.get(IpAuthenticatorFactory.ALLOWED_IP_ADDRESS_CONFIG);*/
    }

    @Override
    public void action(AuthenticationFlowContext context) {
    }

    @Override
    public boolean requiresUser() {
        return true;
    }

    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        return true;
    }

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
    }

    @Override
    public void close() {
    }

}
