package com.algaworks.algafood.auth;

import java.util.Arrays;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.CompositeTokenGranter;
import org.springframework.security.oauth2.provider.TokenGranter;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.redis.RedisTokenStore;

@Configuration
@EnableAuthorizationServer
public class AuthorizationServerConfig extends AuthorizationServerConfigurerAdapter {

	@Autowired
	private PasswordEncoder passwordEncoder;

	@Autowired
	private AuthenticationManager authenticationManager;
	
	@Autowired
	private UserDetailsService userDetailsService;
	
	@Autowired
	private RedisConnectionFactory redisConnectionFactory;

	@Override
	public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
		clients.inMemory() // Aplicação WEB frontend (Password flow)
				.withClient("algafood-web") //
				.secret(passwordEncoder.encode("a9d9p8.E10")) //
				.authorizedGrantTypes("password", "refresh_token") //
				.scopes("write", "read") //
				.accessTokenValiditySeconds(6 * 60 * 60) // 6 Horas (Padrão 12 Horas) horas * minutos * segundos
				.refreshTokenValiditySeconds(60 * 24 * 60 * 60) // 60 Dias (Padrão 30 Dias) dias * horas * minutos * segundos
			
			.and() // Aplicação de BI (Authorization code)
				.withClient("food-analytics") //
				.secret(passwordEncoder.encode("")) //
				.authorizedGrantTypes("authorization_code") //
				.scopes("write", "read") //
				.redirectUris("http://localhost:8082") //
				
			.and() // Aplicação integrador backend (Client credentials)
				.withClient("app-integrador") //
				.secret(passwordEncoder.encode("@app$-integrador")) //
				.authorizedGrantTypes("client_credentials") //
				.scopes("write", "read") //
			
			.and() // Aplicação acessa como ADMIN (Implicit Grant Type)
				.withClient("web-admin") //
				.authorizedGrantTypes("implicit") //
				.scopes("write", "read") //
				.redirectUris("http://localhost:8082") //
				
			.and() // Aplicação do algafood para validar tokens
				.withClient("checktoken") //
				.secret(passwordEncoder.encode("checktoken"));
	}

	@Override
	public void configure(AuthorizationServerSecurityConfigurer security) throws Exception {
		security.checkTokenAccess("permitAll()")
		.allowFormAuthenticationForClients();
	}

	@Override
	public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
		endpoints.authenticationManager(authenticationManager) //
			.userDetailsService(userDetailsService) //
			.reuseRefreshTokens(false) //
			.tokenStore(redisTokenStore()) //
			.tokenGranter(tokenGranter(endpoints));
	}
	
	private TokenStore redisTokenStore() {
		return new RedisTokenStore(redisConnectionFactory);
	}
	
	private TokenGranter tokenGranter(AuthorizationServerEndpointsConfigurer endpoints) {
		var pkceAuthorizationCodeTokenGranter = new PkceAuthorizationCodeTokenGranter(endpoints.getTokenServices(),
				endpoints.getAuthorizationCodeServices(), endpoints.getClientDetailsService(),
				endpoints.getOAuth2RequestFactory());
		
		var granters = Arrays.asList(pkceAuthorizationCodeTokenGranter, endpoints.getTokenGranter());
		
		return new CompositeTokenGranter(granters);
	}

}
