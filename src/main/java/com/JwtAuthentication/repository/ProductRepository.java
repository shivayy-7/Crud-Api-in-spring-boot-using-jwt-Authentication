package com.JwtAuthentication.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import com.JwtAuthentication.api.Product;

public interface ProductRepository extends JpaRepository<Product, Integer> {
	
	Optional<Product> findByEmail(String email);

}
