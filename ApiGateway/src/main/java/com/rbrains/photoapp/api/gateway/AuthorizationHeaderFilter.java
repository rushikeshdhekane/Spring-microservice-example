package com.rbrains.photoapp.api.gateway;

import java.util.Base64;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;

import com.google.common.net.HttpHeaders;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Header;
import io.jsonwebtoken.Jwt;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import reactor.core.publisher.Mono;

@Component
public class AuthorizationHeaderFilter extends AbstractGatewayFilterFactory<AuthorizationHeaderFilter.Config>{

	@Autowired
	private Environment env;
	
	public AuthorizationHeaderFilter() {
		super(Config.class);
	}
	
	public static class Config{
		
	}
	
	@Override
	public GatewayFilter apply(Config config) {
		
		return (exchange, chain)->{
			
			ServerHttpRequest request =  exchange.getRequest();
			
			if(! request.getHeaders().containsKey(HttpHeaders.AUTHORIZATION)) {
				return onError(exchange,"No authoriztion header", HttpStatus.UNAUTHORIZED);
			}
			
			String authorizationHeader = request.getHeaders().get(HttpHeaders.AUTHORIZATION).get(0);
			String jwt = authorizationHeader.replace("Bearer", "");
			
			if(!isJwtValid(jwt)) {
				return onError(exchange, "JWT token is not valid", HttpStatus.UNAUTHORIZED);
			}
			
			return chain.filter(exchange);
		};
	}

	private Mono<Void> onError(ServerWebExchange exchange, String string, HttpStatus unauthorized) {
		ServerHttpResponse response = exchange.getResponse();
		response.setStatusCode(unauthorized);
		
		return response.setComplete();
	}
	
	private boolean isJwtValid(String jwt) {
		boolean returnValue =true;
		
		String subject = null;
		String tokenSecret = env.getProperty("token.secret");
		byte[] secretKeyBytes = Base64.getEncoder().encode(tokenSecret.getBytes());
		SecretKey signingKey = new SecretKeySpec(secretKeyBytes,SignatureAlgorithm.HS512.getJcaName());
		
	 	JwtParser jwtParser = Jwts.parserBuilder()
	 						  .setSigningKey(signingKey)
	 						  .build();
	 	
	 	try {
	 		Jwt<Header, Claims> parsedToken = jwtParser.parse(jwt);
	 		subject = parsedToken.getBody().getSubject(); 
	 	}catch (Exception e) {
	 		returnValue = false;
		}
		
	 	if(subject == null || subject.isEmpty()) {
	 		returnValue = false;
	 	}
	 	
		return returnValue;
	}

}