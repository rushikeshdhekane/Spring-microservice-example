package com.rbrains.photoapp.api.users.security;



import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

import com.rbrains.photoapp.api.users.service.UsersService;

@Configuration
@EnableWebSecurity
public class WebSecurity {

	@Autowired
	private UsersService usersService;
	
	@Autowired
	private Environment environment;
	
	@Autowired
	private BCryptPasswordEncoder bCryptPasswordEncoder;
	
	@Bean
 	public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
 		
		// Configure AuthenticationManagerBuilder 
		AuthenticationManagerBuilder authenticationManagerBuilder = 
			http.getSharedObject(AuthenticationManagerBuilder.class);
		
		authenticationManagerBuilder.userDetailsService(usersService)
		.passwordEncoder(bCryptPasswordEncoder);
		
		AuthenticationManager authenticationManager = authenticationManagerBuilder.build();
		
		//Create authentication filter
		AuthenticationFilter authenticationFilter = 
				new AuthenticationFilter(authenticationManager, usersService, environment);
		
		authenticationFilter.setFilterProcessesUrl("/users/login");
		
		http.csrf().disable();
		
		http.authorizeHttpRequests()
		.antMatchers(HttpMethod.POST, "/users").permitAll()
		.antMatchers("/h2-console/**").permitAll()
		.and()
		.addFilter(authenticationFilter)
		.authenticationManager(authenticationManager)
		.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);

		http.headers().frameOptions().disable();
		
		return http.build();
 	}

}
