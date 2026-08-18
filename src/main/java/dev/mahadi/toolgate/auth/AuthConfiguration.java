package dev.mahadi.toolgate.auth;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.ArrayList;
import java.util.List;

/**
 * Assembles the token validators this deployment actually has.
 *
 * <p>Deciding here rather than with conditional beans keeps the whole rule visible in one
 * place — "which credentials does this gateway accept" is a question that should have one
 * readable answer, in the same spirit as the policy file.
 */
@Configuration
public class AuthConfiguration {

    private static final Logger log = LoggerFactory.getLogger(AuthConfiguration.class);

    @Bean
    TokenValidator tokenValidator(AuthProperties authProps, OidcProperties oidcProps) {
        List<TokenValidator> validators = new ArrayList<>();

        if (oidcProps.enabled()) {
            validators.add(JwtTokenValidator.create(oidcProps, authProps.getResourceUri()));
        }
        if (!authProps.getCallers().isEmpty()) {
            validators.add(new StaticTokenValidator(authProps));
            if (oidcProps.enabled()) {
                log.warn("{} static token(s) remain configured alongside OIDC — these are "
                                + "shared secrets that never expire and name no person; keep "
                                + "them for build agents, not for people",
                        authProps.getCallers().size());
            }
        }
        if (validators.isEmpty() && authProps.isEnabled()) {
            log.error("Authentication is enabled but neither OIDC nor any static caller is "
                    + "configured — every request will be refused");
        }
        return new CompositeTokenValidator(validators, authProps.getResourceUri());
    }
}
