package com.algaworks.algafood.auth;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;

@Configuration
@EnableAuthorizationServer
public class AuthorizationServerConfig extends AuthorizationServerConfigurerAdapter {

	@Autowired
	private PasswordEncoder passwordEncoder;

	@Autowired
	private AuthenticationManager authenticationManager;
	
	@Autowired
	private UserDetailsService userDetailsService;

	@Override
	public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
		clients.inMemory() // Aplicação WEB frontend
				.withClient("algafood-web") //
				.secret(passwordEncoder.encode("a9d9p8.E10")) //
				.authorizedGrantTypes("password", "refresh_token") //
				.scopes("write", "read")
				.accessTokenValiditySeconds(6 * 60 * 60) // 6 Horas (Padrão 12 Horas) dias * horas * minutos * segundos
				.refreshTokenValiditySeconds(60 * 24 * 60 * 60) // 60 Dias (Padrão 30 Dias) dias * horas * minutos * segundos
			.and() // Aplicação integrador backend
				.withClient("app-integrador") //
				.secret(passwordEncoder.encode("@app$-integrador")) //
				.authorizedGrantTypes("client_credentials") //
				.scopes("write", "read") //
			.and() // Aplicação do algafood para validar tokens
				.withClient("checktoken") //
				.secret(passwordEncoder.encode("checktoken"));
	}

	@Override
	public void configure(AuthorizationServerSecurityConfigurer security) throws Exception {
		security.checkTokenAccess("permitAll()");
	}

	@Override
	public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
		endpoints.authenticationManager(authenticationManager) //
			.userDetailsService(userDetailsService) //
			.reuseRefreshTokens(false);
	}

}
