package com.JwtAuthentication.controller;

import java.net.URI;
import java.util.List;

import javax.validation.Valid;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.JwtAuthentication.api.Product;
import com.JwtAuthentication.jwt.JwtTokenUtil;
import com.JwtAuthentication.repository.ProductRepository;
import com.JwtAuthentication.request.AuthRequest;
import com.JwtAuthentication.request.AuthResponse;

@RestController
public class ProductController {
	
	@Autowired ProductRepository repo;
	
	@Autowired PasswordEncoder passwordEncoder;
	
	@Autowired private AuthenticationManager authManager;
	
	@Autowired JwtTokenUtil jwtUtil;
	
	@GetMapping("/products")
	public List<Product> list(){
		return repo.findAll();
	}
	
	@PostMapping("/create")
	public ResponseEntity<Product> create(@RequestBody @Valid Product product){
		product.setPassword(passwordEncoder.encode(product.getPassword()));
		Product saveProduct = repo.save(product);
		URI productURI = URI.create("/create/" + saveProduct.getId());
		
		return ResponseEntity.created(productURI).body(saveProduct);
	}
	
	@PostMapping("/auth/login")
	public ResponseEntity<?> login(@RequestBody @Valid AuthRequest request){
		try {
			Authentication authentication = authManager.authenticate(
			new UsernamePasswordAuthenticationToken(request.getEmail(), request.getPassword())
					);
			Product product = (Product)authentication.getPrincipal();
			
			String accessToken = jwtUtil.generateAccessToken(product);
			AuthResponse response = new AuthResponse(product.getEmail(), accessToken);
			
			return ResponseEntity.ok(response);
			
		} catch (BadCredentialsException e) {
			return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
		}
		
	}
	
	@DeleteMapping("/delete/{id}")
	public ResponseEntity<?> delete(@PathVariable int id){
		
		repo.deleteById(id);
			
			String msg = "deleted successfully  ";
		
		return ResponseEntity.ok(msg);
	}
	
	@PutMapping("/update")
	public ResponseEntity<?> update(@RequestBody @Valid Product product){
		
		product.setPassword(passwordEncoder.encode(product.getPassword()));
		Product saveProduct = repo.save(product);
		URI productURI = URI.create("/update/" + saveProduct.getId());
		
		return ResponseEntity.created(productURI).body(saveProduct);
	}

}
