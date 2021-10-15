package tr.com.softtech.dataplateau.keycloak.jwtauthenticator;

import java.io.*;
import java.net.*;
import java.util.*;

import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.Authenticator;
import org.keycloak.models.*;
import org.json.JSONObject;

public class JWTAuthenticator implements Authenticator {

    private static final Logger logger = Logger.getLogger(JWTAuthenticator.class);


    @Override
    public void authenticate(AuthenticationFlowContext context) {
        RealmModel realm = context.getRealm();
        UserModel user = null;
        String contextAddress = context.getRefreshExecutionUrl().toString();
        String host = contextAddress.substring(0, contextAddress.indexOf("realms"));
        logger.debug(context.getRefreshExecutionUrl().toString());

        try {
            String token = getToken(context.getUriInfo().getQueryParameters().getFirst("redirect_uri"));
            String userName = checkToken(token, realm.getName(), host);
            if (userName.isEmpty())
                throw new Exception("Invalid Token");
            Map<String, String> map = new HashMap();
            map.put("username", userName);
            List<UserModel> users = context.getSession().users().searchForUser(map, realm);
            if (users.get(0).getUsername().isEmpty())
                throw new Exception("There is no userName in Keycloak User List");
            logger.debug(users.get(0).getUsername());
            user = users.get(0);
            logger.debug("Success");
            context.setUser(user);
            context.success();

        } catch (Exception e) {
            logger.error(e.getMessage());
            context.attempted();
        }
    }


    private String getToken(String redirectUri) throws UnsupportedEncodingException {
        logger.debug("Start Get Token");
        Map<String, String> query_pairs = new LinkedHashMap<String, String>();
        try {
            URI url = new URI(redirectUri);
            String query = url.getQuery();
            String[] pairs = query.split("&");
            for (String pair : pairs) {
                int idx = pair.indexOf("=");
                query_pairs.put(URLDecoder.decode(pair.substring(0, idx), "UTF-8"), URLDecoder.decode(pair.substring(idx + 1), "UTF-8"));
            }
        } catch (Exception ex) {
            logger.error(ex.getMessage());
        }
        logger.debug("getToken");
        logger.debug(query_pairs.get("jwt"));
        return query_pairs.get("jwt");
    }

    private String checkToken(String token, String realmName, String host) {
        String result = "";
        try {
            String endPoint = host + "realms/" + realmName + "/protocol/openid-connect/userinfo" ;
            logger.debug(endPoint);
            URL url = new URL(endPoint);
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setDoOutput(true);
            conn.setRequestMethod("GET");
            conn.setRequestProperty("Authorization", "Bearer " + token);
            conn.setRequestProperty("Content-Type", "application/json");


            if (conn.getResponseCode() != HttpURLConnection.HTTP_OK) {
                logger.errorf("Error Response Code %s ", conn.getResponseCode());
                throw new RuntimeException("Failed : HTTP error code : " + conn.getResponseCode());
            }
            BufferedReader br = new BufferedReader(new InputStreamReader((conn.getInputStream())));

            String output;
            while ((output = br.readLine()) != null) {
                JSONObject jsonMessage = new JSONObject(output);
                result = jsonMessage.get("preferred_username").toString();
                logger.debug(result);
            }
            conn.disconnect();

        } catch (Exception e) {
            result = "";
            logger.errorf("checkToken error %s ", e.getMessage());
        }
        return result;
    }

    @Override
    public void action(AuthenticationFlowContext authenticationFlowContext) {

    }

    @Override
    public boolean requiresUser() {
        return false;
    }

    @Override
    public boolean configuredFor(KeycloakSession keycloakSession, RealmModel realmModel, UserModel userModel) {
        return false;
    }

    @Override
    public void setRequiredActions(KeycloakSession keycloakSession, RealmModel realmModel, UserModel userModel) {

    }


    @Override
    public void close() {

    }
}
