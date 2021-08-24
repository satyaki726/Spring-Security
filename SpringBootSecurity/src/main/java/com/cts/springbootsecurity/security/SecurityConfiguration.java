package com.cts.springbootsecurity.security;

//import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
//import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@EnableWebSecurity
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {

	

	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		// TODO Auto-generated method stub
		PasswordEncoder encoder = PasswordEncoderFactories.createDelegatingPasswordEncoder();
		auth.inMemoryAuthentication()
		        .withUser("Satyaki")
		        .password(encoder.encode("9732"))
		        .roles("USER")
		        .and()
		        .withUser("Rima")
		        .password(encoder.encode("2580"))
		        .roles("ADMIN");
	}
	
	@Override
	protected void configure(HttpSecurity http) throws Exception {
		// TODO Auto-generated method stub
		http.authorizeRequests()
		    .antMatchers("/admin").hasRole("ADMIN")
		    .antMatchers("/user").hasAnyRole("USER","ADMIN")
			.antMatchers("/").permitAll()
			.and().formLogin();
			
	}
	
	/*
	@Bean
	public PasswordEncoder getPasswordEncoder() {
		return NoOpPasswordEncoder.getInstance();
	}*/
}
