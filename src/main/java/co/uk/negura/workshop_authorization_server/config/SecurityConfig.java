package co.uk.negura.workshop_authorization_server.config;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.MediaType;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.UUID;

/**
    * This class is responsible for configuring the security of the application.
    * It configures OAuth2 and OIDC support, user details service, and JWT token support.
    * It is annotated with @Configuration to indicate that it is a Spring configuration class.
    * It is annotated with @EnableWebSecurity to enable Spring Security’s web security support.
 */
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    /**
    *The authorizationServerSecurityFilterChain is configured to handle the security aspects specifically related to OAuth2
    * and OpenID Connect (OIDC) authorization, such as token issuance, token introspection, and user consent.
    * This filter chain is tailored to manage the endpoints and security requirements that are unique to an authorization server.
    *
    * The defaultSecurityFilterChain, on the other hand, is configured for the general security of your application,
    * handling aspects like user authentication, form login, and securing other non-OAuth2/OIDC endpoints.
    *
    * Applying authorizationServerSecurityFilterChain before defaultSecurityFilterChain ensures that requests to
    * OAuth2/OIDC endpoints are processed by the specialized security configurations first. This is crucial because:
    * 1. Priority Handling: OAuth2/OIDC requests need to be intercepted and processed by the authorization server
    *   configurations before any general security processing takes place.
    *   This ensures that the OAuth2/OIDC flows work correctly and securely.
     */

    /**
        * This method configures the security filter chain for the authorization server.
        * It configures the authorization server security, OpenID Connect 1.0 support, and OAuth 2.0 resource server support.
        * It is annotated with @Bean to indicate that it is a Spring bean.
        * It is annotated with @Order(1) to indicate that it should be applied before the default security filter chain.
        * It takes an HttpSecurity object as an argument to configure the security filter chain.
        * It returns a SecurityFilterChain object.
     */
    @Bean
    @Order(1)
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http)
            throws Exception {
        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);
        http.getConfigurer(OAuth2AuthorizationServerConfigurer.class)
                .oidc(Customizer.withDefaults());	// Enable OpenID Connect 1.0
        http
                // Redirect to the login page when not authenticated from the
                // authorization endpoint
                .exceptionHandling((exceptions) -> exceptions
                        .defaultAuthenticationEntryPointFor(
                                new LoginUrlAuthenticationEntryPoint("/login"),
                                new MediaTypeRequestMatcher(MediaType.TEXT_HTML)
                        )
                )
                // Accept access tokens for User Info and/or Client Registration
                .oauth2ResourceServer((resourceServer) -> resourceServer
                        .jwt(Customizer.withDefaults()));

        return http.build();
    }

    /**
        * This method configures the security filter chain for the default security configuration.
        * It configures the default security filter chain with form login support.
        * It is annotated with @Bean to indicate that it is a Spring bean.
        * It is annotated with @Order(2) to indicate that it should be applied after the authorization server security filter chain.
        * It takes an HttpSecurity object as an argument to configure the security filter chain.
        * It returns a SecurityFilterChain object.
     */
    @Bean
    @Order(2)
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http)
            throws Exception {
        http
                .authorizeHttpRequests((authorize) -> authorize
                        .anyRequest().authenticated()
                )
                // Form login handles the redirect to the login page from the
                // authorization server filter chain
                .formLogin(Customizer.withDefaults());

        return http.build();
    }

    /**
     * This method configures the user details service with a single user.
     * It is annotated with @Bean to indicate that it is a Spring bean.
     * @return a UserDetailsService object.
     */
    @Bean
    public UserDetailsService userDetailsService() {
        UserDetails userDetails = User.withDefaultPasswordEncoder()
                .username("user")
                .password("password")
                .roles("USER")
                .build();

        return new InMemoryUserDetailsManager(userDetails);
    }

    /**
     * The RegisteredClientRepository is a component in Spring Security used for managing OAuth 2.0 clients
     * in an authorization server. It's like a storage or database where information about clients
     * (applications that can request tokens) is kept. Here's a breakdown of its role and how it works,
     * especially in the context of the provided code:
     *
     * Client Registration: Before an application can request tokens from an authorization server,
     * it must be registered. This registration process involves specifying details about the client,
     * such as its ID, secret, authorized grant types (ways to obtain tokens), and redirect URIs
     * (where to send tokens after authentication).
     *
     * Storage: The RegisteredClientRepository acts as a storage for these client registrations.
     * It can be backed by various storage mechanisms, such as in-memory, database, or custom
     * implementations, depending on the application's needs.
     *
     * Lookup: During the OAuth 2.0 authorization process, the authorization server needs to look
     * up client details to validate requests. For example, when a client requests a token, the server
     * uses the RegisteredClientRepository to check if the client ID and secret match a registered client
     * and if the requested grant type is allowed for that client.
     *
     * In-Memory Implementation: In the provided code, an in-memory version of the RegisteredClientRepository is used.
     * This means client registrations are stored in memory. It's simple and useful for development or testing but not
     * recommended for production environments due to its ephemeral nature (data is lost when the application restarts).
     *
     * Example Usage: The method registeredClientRepository() in the code creates a single RegisteredClient with specific settings
     * (client ID, secret, grant types, etc.) and stores it in an InMemoryRegisteredClientRepository.
     * This client can then participate in the OAuth 2.0 flow, requesting tokens from the authorization server.
     *
     * In summary, the RegisteredClientRepository is crucial for managing client registrations in an OAuth 2.0 authorization server,
     * acting as the source of truth for client details during the authorization process.
     */

    /**
     * This method configures the registered client repository with a single OIDC client.
     * It is annotated with @Bean to indicate that it is a Spring bean.
     * @return a RegisteredClientRepository object.
     */
    @Bean
    public RegisteredClientRepository registeredClientRepository() {
        RegisteredClient oidcClient = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId("oidc-client")
                .clientSecret("{noop}secret")
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .redirectUri("http://127.0.0.1:8080/login/oauth2/code/oidc-client")
                .postLogoutRedirectUri("http://127.0.0.1:8080/")
                .scope(OidcScopes.OPENID)
                .scope(OidcScopes.PROFILE)
                .clientSettings(ClientSettings.builder().requireAuthorizationConsent(true).build())
                .build();

        return new InMemoryRegisteredClientRepository(oidcClient);
    }

    /**
     * The jwkSource() method is designed to create and provide a source of JSON Web Keys (JWKs) for your application.
     * JWKs are a compact format for representing cryptographic keys used by JSON Web Tokens (JWTs) for signing and/or encryption.
     *
     * Key Pair Generation: The method starts by generating a new RSA key pair. RSA is a widely used algorithm for public-key cryptography.
     * The key pair consists of a public key, which can be shared, and a private key, which must be kept secret. The generateRsaKey() helper
     * method is called to perform this task.
     *
     * RSAKey Creation: With the generated RSA key pair, an RSAKey object is created using the builder pattern.
     * The builder is provided with the public key, the private key, and a unique identifier for the key (keyID).
     * This RSAKey object represents the JWK that will be used for signing JWTs.
     *
     * JWKSet Creation: A JWKSet is a collection of JWKs. In this case, the JWKSet is created with just one RSAKey.
     * However, a JWKSet can contain multiple keys if needed
     *
     * ImmutableJWKSet: The JWKSet is wrapped in an ImmutableJWKSet object. This makes the set of keys immutable,
     * meaning it cannot be changed after creation. This is important for security, ensuring that the keys cannot be tampered with.
     *
     * Return JWKSource: Finally, the method returns the ImmutableJWKSet as a JWKSource<SecurityContext>. T
     * his JWKSource can then be used by other parts of the Spring Security framework, particularly the OAuth2 authorization server,
     * to sign JWTs or to provide public keys to clients for verifying JWT signatures.
     *
     * In summary, the jwkSource() method sets up the cryptographic keys your authorization server will use for signing JWTs,
     * ensuring secure token issuance and validation.
     */

    /**
     * This method configures the JWK source with a generated RSA key pair.
     * It is annotated with @Bean to indicate that it is a Spring bean.
     * @return a JWKSource object.
     */
    @Bean
    public JWKSource<SecurityContext> jwkSource() {
        KeyPair keyPair = generateRsaKey();
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
        RSAKey rsaKey = new RSAKey.Builder(publicKey)
                .privateKey(privateKey)
                .keyID(UUID.randomUUID().toString())
                .build();
        JWKSet jwkSet = new JWKSet(rsaKey);
        return new ImmutableJWKSet<>(jwkSet);
    }

    /**
     * This method generates an RSA key pair for use in JWT signing.
     * It is a helper method used by the jwkSource() method.
     * @return a KeyPair object.
     */
    private static KeyPair generateRsaKey() {
        KeyPair keyPair;
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);
            keyPair = keyPairGenerator.generateKeyPair();
        }
        catch (Exception ex) {
            throw new IllegalStateException(ex);
        }
        return keyPair;
    }

    /**
     * The jwtDecoder() method is responsible for creating and configuring a JWT decoder for your application.
     * A JWT decoder is used to verify and decode JWTs, allowing your application to validate tokens issued by an authorization server.
     * @param jwkSource The JWK source containing the cryptographic keys used for JWT signing.
     * @return a JwtDecoder object.
     */
    @Bean
    public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
    }

    /**
     * The authorizationServerSettings() method creates an AuthorizationServerSettings object with default settings.
     * This object is used to configure various settings for the authorization server, such as token expiration, consent requirements, and more.
     * @return an AuthorizationServerSettings object.
     */
    @Bean
    public AuthorizationServerSettings authorizationServerSettings() {
        return AuthorizationServerSettings.builder().build();
    }
}
