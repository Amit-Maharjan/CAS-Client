package com.maharjan.cas_client.config;

import org.jasig.cas.client.validation.Cas30ServiceTicketValidator;
import org.springframework.beans.factory.annotation.Value;
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

    @Value("${cas.server.url}")
    private String casServerUrl;

    @Value("${cas.client.service-url}")
    private String serviceUrl;

    @Value("${cas.client.logout-redirect-url}")
    private String logoutRedirectUrl;

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
                .logoutSuccessUrl(casServerUrl + "/logout?service=" + logoutRedirectUrl)
                .and()
                .csrf().disable()
                .authenticationProvider(casAuthenticationProvider())
                .addFilter(casAuthenticationFilter());
    }

    @Bean
    public ServiceProperties serviceProperties() {
        ServiceProperties properties = new ServiceProperties();
        properties.setService(serviceUrl); // must match the one in CAS server config
        properties.setSendRenew(false);
        return properties;
    }

    @Bean
    public CasAuthenticationProvider casAuthenticationProvider() {
        CasAuthenticationProvider provider = new CasAuthenticationProvider();
        provider.setServiceProperties(serviceProperties());
        provider.setTicketValidator(new Cas30ServiceTicketValidator(casServerUrl));
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
        entryPoint.setLoginUrl(casServerUrl + "/login");
        entryPoint.setServiceProperties(serviceProperties);
        return entryPoint;
    }

    @Bean
    public LogoutFilter logoutFilter() {
        return new LogoutFilter(casServerUrl + "/logout", new SecurityContextLogoutHandler());
    }
}