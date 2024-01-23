package com.capgemini.springboot.demosecurity.security;

import javax.sql.DataSource;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.provisioning.UserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class DemoSecurityConfig {
	
	@Bean
	public UserDetailsManager userDetailsManager(DataSource dataSource) {
		JdbcUserDetailsManager jdbcUserDetailsManager = new JdbcUserDetailsManager(dataSource);
		//define query to retrieve user by username
		jdbcUserDetailsManager.setUsersByUsernameQuery("SELECT user_id, pw, active FROM members where user_id=?");
		//define query to retrieve user by roles
		jdbcUserDetailsManager.setAuthoritiesByUsernameQuery("SELECT user_id, role FROM roles where user_id=?");
		
		return jdbcUserDetailsManager;
	}
	//Default spring security
	/*@Bean
	public UserDetailsManager userDetailsManager(DataSource dataSource) {
		
		return new JdbcUserDetailsManager(dataSource);
		
	}
	*/
	
	@Bean
	public SecurityFilterChain filterChain(HttpSecurity http) throws Exception
	{
		http.authorizeHttpRequests(configurer ->
				configurer.
				requestMatchers("/").hasRole("EMPLOYEE").
			  requestMatchers("/leaders/**").hasRole("MANAGER").
			  requestMatchers("/systems/**").hasRole("ADMIN").
    			anyRequest().authenticated()
		).formLogin(form -> 
						form.loginPage("/showMyLoginPage")
							.loginProcessingUrl("/authenticateTheUser")
							.permitAll())
		.logout( logout -> logout.permitAll())
		.exceptionHandling(configurer -> configurer.accessDeniedPage("/access-denied"))
		;
	
		
		return http.build();
		
	}
	/*
	 * InMemory Database from security jar file
	 *@Bean
	public InMemoryUserDetailsManager userDetailsManager() {
		UserDetails john = User.builder().username("john")
				.password("{noop}test123")
				.roles("EMPLOYEE")
				.build();
		
		UserDetails mary = User.builder().username("mary")
				.password("{noop}test123")
				.roles("EMPLOYEE","MANAGER")
				.build();
		
		UserDetails susan = User.builder().username("susan")
				.password("{noop}test")
				.roles("EMPLOYEE","MANAGER","ADMIN")
				.build();
		return new InMemoryUserDetailsManager(john,mary,susan);
		
	}*/

}
