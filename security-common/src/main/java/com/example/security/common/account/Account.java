package com.example.security.common.account;

import jakarta.persistence.CollectionTable;
import jakarta.persistence.Column;
import jakarta.persistence.ElementCollection;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.Table;

import java.util.HashSet;
import java.util.Set;

@Entity
@Table(name = "account")
public class Account {

	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	private Long id;

	@Column(nullable = false, unique = true, length = 254)
	private String email;

	@Column(name = "password_hash", nullable = false, length = 100)
	private String passwordHash;

	@ElementCollection(fetch = FetchType.EAGER)
	@CollectionTable(name = "account_permission", joinColumns = @JoinColumn(name = "account_id"))
	@Column(name = "permission")
	@Enumerated(EnumType.STRING)
	private Set<Permission> permissions = new HashSet<>();

	protected Account() {
	}

	public Account(String email, String passwordHash, Set<Permission> permissions) {
		this.email = email;
		this.passwordHash = passwordHash;
		this.permissions = new HashSet<>(permissions);
	}

	public String getEmail() {
		return email;
	}

	public String getPasswordHash() {
		return passwordHash;
	}

	public Set<Permission> getPermissions() {
		return Set.copyOf(permissions);
	}
}
