package com.maharjan.cas_client.config;

import org.jasig.cas.client.validation.Cas30ServiceTicketValidator;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.cas.ServiceProperties;
import org.springframework.security.cas.authentication.CasAuthenticationProvider;
import org.springframework.security.cas.web.CasAuthenticationEntryPoint;
import org.springframework.security.cas.web.CasAuthenticationFilter;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.authentication.logout.LogoutFilter;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;

import java.util.List;

@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    private static final String CAS_SERVER_URL = "https://localhost:8443";
    private static final String SERVICE_URL = "http://localhost:8080/login/cas";

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .authorizeRequests()
                .antMatchers("/error").permitAll()
                .anyRequest().authenticated()
                .and()
                .exceptionHandling()
                .authenticationEntryPoint(casAuthenticationEntryPoint(serviceProperties()))
                .accessDeniedPage("/403")
                .and()
                .logout()
                .logoutSuccessUrl(CAS_SERVER_URL + "/logout?service=http://localhost:8080")
                .and()
                .csrf().disable()
                .authenticationProvider(casAuthenticationProvider())
                .addFilter(casAuthenticationFilter());
    }

    @Bean
    public ServiceProperties serviceProperties() {
        ServiceProperties properties = new ServiceProperties();
        properties.setService(SERVICE_URL); // must match the one in CAS server config
        properties.setSendRenew(false);
        return properties;
    }

    @Bean
    public CasAuthenticationProvider casAuthenticationProvider() {
        CasAuthenticationProvider provider = new CasAuthenticationProvider();
        provider.setServiceProperties(serviceProperties());
        provider.setTicketValidator(new Cas30ServiceTicketValidator(CAS_SERVER_URL));
        provider.setAuthenticationUserDetailsService(
                assertion -> new User(
                        assertion.getName(),
                        "",
                        List.of(new SimpleGrantedAuthority("ROLE_USER"))
                )
        );
        provider.setKey("casProviderKey");
        return provider;
    }

    @Bean
    public CasAuthenticationFilter casAuthenticationFilter() throws Exception {
        CasAuthenticationFilter filter = new CasAuthenticationFilter();
        filter.setFilterProcessesUrl("/login/cas"); // this must match the service URL path
        filter.setAuthenticationManager(authenticationManager());
        return filter;
    }

    @Bean
    public CasAuthenticationEntryPoint casAuthenticationEntryPoint(ServiceProperties serviceProperties) {
        CasAuthenticationEntryPoint entryPoint = new CasAuthenticationEntryPoint();
        entryPoint.setLoginUrl(CAS_SERVER_URL + "/login");
        entryPoint.setServiceProperties(serviceProperties);
        return entryPoint;
    }

    @Bean
    public LogoutFilter logoutFilter() {
        return new LogoutFilter(CAS_SERVER_URL + "/logout", new SecurityContextLogoutHandler());
    }
}