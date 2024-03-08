package keycloak.condition.ip;

import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.authenticators.conditional.ConditionalAuthenticator;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

public class ConditionalIpAuthenticator implements ConditionalAuthenticator {

    public static final ConditionalIpAuthenticator SINGLETON = new ConditionalIpAuthenticator();
    private static final Logger LOG = Logger.getLogger(ConditionalIpAuthenticator.class);

    @Override
    public boolean matchCondition(AuthenticationFlowContext context) {
        UserModel user = context.getUser();
        String remoteIPAddress = context.getConnection().getRemoteAddr();

        //AuthenticatorConfigModel authConfig = context.getAuthenticatorConfig();
        if (user != null) {
            //boolean resultInversion = Boolean.valueOf(authConfig.getConfig().get(ConditionalIpAuthenticatorFactory.COND_IP_INVERSION));
            boolean shouldAllow = shouldAllowWithoutFlowChange(user, remoteIPAddress);
            System.out.println("Should allow without flow change: " + shouldAllow);
            return !shouldAllow /*^ resultInversion*/;
        }
        return false;
    }

    @Override
    public void action(AuthenticationFlowContext afc) {
        // Not used
    }

    @Override
    public boolean requiresUser() {
        return true;
    }

    @Override
    public void setRequiredActions(KeycloakSession ks, RealmModel rm, UserModel um) {
        // Not used
    }

    @Override
    public void close() {
        // Not used
    }

    private boolean shouldAllowWithoutFlowChange(UserModel user, String remoteIPAddress) {
        //TODO implement logic here
        return "alice".equals(user.getUsername());
    }

}