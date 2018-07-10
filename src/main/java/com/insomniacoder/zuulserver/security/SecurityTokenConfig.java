package com.insomniacoder.zuulserver.security;

import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.http.HttpServletResponse;

@EnableWebSecurity
public class SecurityTokenConfig extends WebSecurityConfigurerAdapter {

    private final String AUTHENTICATION_URL = "/auth/**";
    private final String ADMIN_URL = "/admin/**";

    @Override
    protected void configure(HttpSecurity http) throws Exception {

        http
                //disable cross-site request forgery
                .csrf().disable()
                // make sure we use stateless session; session won't be used to store user's state. no cookies
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                // handle an unauthorized attempts
                .exceptionHandling().authenticationEntryPoint((req, rsp, e) -> rsp.sendError(HttpServletResponse.SC_UNAUTHORIZED))
                .and()
                // Add a filter to validate the tokens with every request after UsernamePasswordAuthenticationFilter
                .addFilterAfter(new JwtTokenAuthenticationFilter(), UsernamePasswordAuthenticationFilter.class)
                // authorization requests config
                .authorizeRequests()
                //allow POST calls to /auth/**
                .antMatchers(HttpMethod.POST, AUTHENTICATION_URL).permitAll()
                //allow ADMIN user to access all admin endpoints
                .antMatchers(ADMIN_URL).hasRole("ADMIN")
                //others request has to be authenticated to be able to access
                .anyRequest().authenticated();
    }

}