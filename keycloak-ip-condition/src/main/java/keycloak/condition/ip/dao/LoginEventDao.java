package keycloak.condition.ip.dao;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.LinkedList;
import java.util.List;

public class LoginEventDao {

    private static Connection connection;

    //TODO refactor
    public static List<String> getUserIps(String userId, String clientId) {
        List<String> ips = new LinkedList<>();
        createConnection();

        String query = "select distinct(ip_address) from event_entity ee where ee.type = 'CODE_TO_TOKEN' and ee.user_id=? and ee.client_id=?";
        try (PreparedStatement stmt = connection.prepareStatement(query)) {
            stmt.setString(1, userId);
            stmt.setString(2, clientId);
            ResultSet rs = stmt.executeQuery();
            while (rs.next()) {
                ips.add(rs.getString(1));
            }
        } catch (SQLException e) {
            //TODO proper logging
            e.printStackTrace();
        } finally {
            if (connection != null) {
                try {
                    connection.close();
                } catch (SQLException e) {
                    //TODO proper logging
                    e.printStackTrace();
                }
            }
        }

        return ips;
    }

    private static void createConnection() {
        try {
            if (connection == null || connection.isClosed()) {
                connection = getConnection();
            }
        } catch (ClassNotFoundException | SQLException e) {
            //TODO proper logging
            e.printStackTrace();
        }

    }

    //TODO properties
    private static Connection getConnection() throws ClassNotFoundException, SQLException {
        Class.forName("org.postgresql.Driver");
        return DriverManager.getConnection(
                "jdbc:postgresql://postgres:5432/keycloak", "keycloak", "password");
    }
}
