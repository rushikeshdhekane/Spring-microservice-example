package com.rbrains.photoapp.api.users.security;

import java.io.IOException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Date;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.env.Environment;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.rbrains.photoapp.api.users.service.UsersService;
import com.rbrains.photoapp.api.users.shared.UserDto;
import com.rbrains.photoapp.api.users.ui.model.LoginRequestModel;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

public class AuthenticationFilter extends UsernamePasswordAuthenticationFilter{

	private UsersService usersService;
	
	private Environment environment;
	
	public AuthenticationFilter(AuthenticationManager authenticationManager,
			UsersService usersService,
			Environment environment) {
		super(authenticationManager);
		this.usersService =  usersService;
		this.environment = environment;
	}
	
	@Override
	public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
			throws AuthenticationException {
		
			try {
				LoginRequestModel creds = new ObjectMapper()
						.readValue(request.getInputStream(), LoginRequestModel.class);
				
				return getAuthenticationManager().authenticate(
						new UsernamePasswordAuthenticationToken(
								creds.getEmail(), 
								creds.getPassword(), 
								new ArrayList<>()));
			}catch (IOException e) {
				throw new RuntimeException(e);
			}
	}

	@Override
	protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain,
			Authentication authResult) throws IOException, ServletException {
		
		String userName = ((User)authResult.getPrincipal()).getUsername();
		UserDto userDetails =  usersService.getUserDetailsByEmail(userName);
		String tokenSecret = environment.getProperty("token.secret");
		byte[] scretKeyBytes = Base64.getEncoder().encode(tokenSecret.getBytes());
		SecretKey secretKey = new SecretKeySpec(scretKeyBytes, SignatureAlgorithm.HS512.getJcaName());
		
		//jwt token code
		//jwt acces token
		Instant now = Instant.now();
		
		String token = Jwts.builder()
		.setSubject(userDetails.getUserId())
		.setExpiration(Date.from(now.plusMillis(Long.parseLong(environment.getProperty("token.expiration_time")))))
		.setIssuedAt(Date.from(now))
		.signWith(secretKey,SignatureAlgorithm.HS512)
		.compact();
		
		response.addHeader("token", token);
		response.addHeader("userId", userDetails.getUserId());
	}
	
	
	
	
}
