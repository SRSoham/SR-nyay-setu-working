package com.nyaysetu.backend.config;

import com.nyaysetu.backend.filter.JwtAuthFilter;

import com.nyaysetu.backend.filter.RateLimitFilter;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.env.Environment;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

@Configuration
@RequiredArgsConstructor
public class SecurityConfig {

    private static final Logger logger = LoggerFactory.getLogger(SecurityConfig.class);
    private static final String DEFAULT_JWT_SECRET = "nyaysetu-2024-secure-jwt-signing-key-minimum-256-bits-required";

    private final UserDetailsService userDetailsService;
    private final RateLimitFilter rateLimitFilter;
    private final Environment environment;

    @Value("${cors.allowed.origins}")
    private String allowedOrigins;

    @Value("${jwt.secret}")
    private String jwtSecret;

    @PostConstruct
    public void validateJwtSecretConfiguration() {
        boolean isProd = java.util.Arrays.stream(environment.getActiveProfiles())
                .anyMatch("prod"::equalsIgnoreCase);
        boolean isDev = java.util.Arrays.stream(environment.getActiveProfiles())
                .anyMatch("dev"::equalsIgnoreCase);
        String jwtSecretEnv = System.getenv("JWT_SECRET");
        boolean isJwtSecretEnvMissing = jwtSecretEnv == null || jwtSecretEnv.trim().isEmpty();
        boolean isUsingDefaultSecret = DEFAULT_JWT_SECRET.equals(jwtSecret);

        if (isProd && (isJwtSecretEnvMissing || isUsingDefaultSecret)) {
            throw new IllegalStateException(
                    "Security configuration error: JWT_SECRET environment variable is required in production. "
                            + "Application startup is blocked to prevent using an insecure default JWT signing key.");
        }

        if (isDev && isUsingDefaultSecret) {
            logger.warn("JWT secret is using the default fallback value. Set JWT_SECRET in your environment for safer development setup.");
        }
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public AuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setUserDetailsService(userDetailsService);
        provider.setPasswordEncoder(passwordEncoder());
        return provider;
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();


        // SAFE DEFAULT (Localhost fallback)
        List<String> defaultOrigins = Arrays.asList(
                "http://localhost:5173",
                "http://localhost:3000",
                "http://localhost"
        );

        if (allowedOrigins != null && !allowedOrigins.trim().isEmpty()) {
            List<String> origins = Arrays.stream(allowedOrigins.split(","))
                    .map(String::trim)
                    .filter(s -> !s.isEmpty())
                    .collect(Collectors.toList());

            if (origins.contains("*")) {
                // SECURITY: Reject bare "*" when credentials are true
                logger.warn("CORS_ALLOWED_ORIGINS contains bare '*'. This is unsafe with credentials. Falling back to localhost defaults.");
                configuration.setAllowedOrigins(defaultOrigins);
            } else if (origins.stream().anyMatch(o -> o.contains("*"))) {
                // Specific patterns like https://*.example.com are safe
                configuration.setAllowedOriginPatterns(origins);
            } else {
                // Exact valid domains
                configuration.setAllowedOrigins(origins);
            }
        } else {
            // Fallback if environment variable is missing
            configuration.setAllowedOrigins(defaultOrigins);
        }

        // SECURITY IMPROVEMENTS:
        // 1. Always allow credentials for the resolved safe origins
        configuration.setAllowCredentials(true);

        // 2. Add "PATCH" to allowed methods
        configuration.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"));

        // 3. Restrict headers instead of using wildcard "*" for better security
        configuration.setAllowedHeaders(Arrays.asList(
                "Authorization",
                "Content-Type",
                "Accept",
                "Origin",
                "X-Requested-With"
        ));

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }
    @Bean
    public SecurityFilterChain securityFilterChain(
            HttpSecurity http,
            JwtAuthFilter jwtAuthFilter) throws Exception {

        http
                // 1. CORS fix (Restricting to specific origins instead of all)
                .cors(cors -> cors.configurationSource(corsConfigurationSource()))
                .csrf(csrf -> csrf.disable())
                .authorizeHttpRequests(auth -> auth
                        // 2. Only strictly public endpoints allowed
                        .requestMatchers("/api/auth/register", "/api/auth/login", "/api/auth/forgot-password").permitAll()
                        .requestMatchers("/api/health/**").permitAll()
                        .requestMatchers("/v3/api-docs/**", "/swagger-ui/**").permitAll()
                        .requestMatchers("/ws/**").permitAll()

                        // 3. The exact fix for the bug: Everything else MUST be authenticated
                        .anyRequest().authenticated()
                )

                .sessionManagement(sess -> sess.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authenticationProvider(authenticationProvider())
                .addFilterBefore(rateLimitFilter, UsernamePasswordAuthenticationFilter.class)
                .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }
}