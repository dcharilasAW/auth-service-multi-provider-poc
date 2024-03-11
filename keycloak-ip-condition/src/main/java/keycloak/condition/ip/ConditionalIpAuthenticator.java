package keycloak.condition.ip;

import keycloak.condition.ip.dao.LoginEventDao;
import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.authenticators.conditional.ConditionalAuthenticator;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

import java.util.List;

public class ConditionalIpAuthenticator implements ConditionalAuthenticator {

    private LoginEventDao repository = new LoginEventDao();

    public static final ConditionalIpAuthenticator SINGLETON = new ConditionalIpAuthenticator();
    private static final Logger LOG = Logger.getLogger(ConditionalIpAuthenticator.class);

    @Override
    public boolean matchCondition(AuthenticationFlowContext context) {
        UserModel user = context.getUser();
        String clientId = context.getEvent().getEvent().getClientId();
        String remoteIPAddress = context.getConnection().getRemoteAddr();

        if (user != null) {
            boolean shouldAllow = shouldAllowWithoutFlowChange(user.getId(), clientId, remoteIPAddress);
            LOG.info("Should allow without flow change: " + shouldAllow);
            return !shouldAllow;
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

    private boolean shouldAllowWithoutFlowChange(String userId, String clientId, String remoteIPAddress) {
        List<String> ips = repository.getUserIps(userId,clientId);
        return ips.contains(remoteIPAddress);
    }

}