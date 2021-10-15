# keycloak-custom-authenticator-jwt-iframe
Keycloak Custom Authenticator for JWT Token Validation with IFrame Java

# keycloak-jwt-authenticator
This is a simple Keycloak Java Authenticator that checks if the user is coming with trusted JWT. 
If the user is coming with trusted JWT then login form is skipped. 
If the user is coming with non-trusted JWT login form is forced.


## build

Make sure that Keycloak SPI dependencies and your Keycloak server versions match. Keycloak SPI dependencies version is configured in `pom.xml` in the `keycloak.version` property.  

To build the project execute the following command:

```bash
mvn package
```

## deploy

And then, assuming `$KEYCLOAK_HOME` is pointing to you Keycloak installation, just copy it into deployments directory:
 
```bash
cp target/keycloak-ip-authenticator.jar $KEYCLOAK_HOME/standalone/deployments/
```

