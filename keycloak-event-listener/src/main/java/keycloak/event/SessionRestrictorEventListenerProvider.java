package keycloak.event;

import org.keycloak.events.Event;
import org.keycloak.events.EventListenerProvider;
import org.keycloak.events.admin.AdminEvent;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserSessionModel;

import java.util.LinkedList;
import java.util.stream.Collectors;

import static keycloak.event.util.LogUtils.logEvent;

public class SessionRestrictorEventListenerProvider implements EventListenerProvider {

    private final static String PARENT_CLIENT_ID = "webapp-client";

    private final KeycloakSession keycloakSession;

    public SessionRestrictorEventListenerProvider(KeycloakSession keycloakSession) {
        this.keycloakSession = keycloakSession;
    }

    @Override
    public void onEvent(Event event) {
        System.out.println("Event Occurred:" + logEvent(event));

        RealmModel realm;
        ClientModel client;
        UserModel user;

        switch (event.getType()) {
            case CODE_TO_TOKEN:
            case TOKEN_EXCHANGE:
                realm = keycloakSession.getContext().getRealm();
                client = keycloakSession.getContext().getClient();

                RealmModel finalRealm = realm;
                // get all sessions for same client
                keycloakSession.sessions().getUserSessionsStream(realm, client)
                        .filter(userSession -> {
                            boolean sameUser = event.getUserId().equals(userSession.getUser().getId());
                            boolean sameSession = userSession.getId().equals(event.getSessionId());
                            return sameUser && !sameSession;
                        })
                        .collect(Collectors.collectingAndThen(Collectors.toList(), c -> !c.isEmpty() ? c : new LinkedList<UserSessionModel>()))
                        .forEach(userSession -> {
                            // remove all existing user sessions but the current one (last one wins)
                             if (!userSession.getId().equals(event.getSessionId())) {
                                keycloakSession.sessions().removeUserSession(finalRealm, userSession);
                            }
                        });
                break;
            case LOGOUT:
                realm = keycloakSession.getContext().getRealm();
                user = keycloakSession.users().getUserById(realm,event.getUserId());

                RealmModel finalRealm1 = realm;
                // get all sessions for same user
                keycloakSession.sessions().getUserSessionsStream(realm, user)
                        .collect(Collectors.collectingAndThen(Collectors.toList(), c -> !c.isEmpty() ? c : new LinkedList<UserSessionModel>()))
                        .forEach(userSession -> {
                            // remove all sessions if main app logs out. otherwise, log out only the same session
                            if (PARENT_CLIENT_ID.equals(event.getClientId()) || userSession.getId().equals(event.getSessionId())) {
                                keycloakSession.sessions().removeUserSession(finalRealm1, userSession);
                            }
                        });
                break;
        }
    }

    @Override
    public void onEvent(AdminEvent event, boolean includeRepresentation) {
        System.out.println("Admin Event Occurred:" + logEvent(event));
    }

    @Override
    public void close() {
    }


}
