package com.algaworks.algafood.auth.core;

import java.util.Collections;

import com.algaworks.algafood.auth.domain.model.User;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class AuthUser extends org.springframework.security.core.userdetails.User {
		
	private static final long serialVersionUID = 1L;
	
	private Long userId;
	private String fullName;
	
	public AuthUser(User user) {
		super(user.getEmail(), user.getPassword(), Collections.emptyList());
		
		this.userId = user.getId();
		this.fullName = user.getName();
	}

}
