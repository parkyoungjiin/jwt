package com.cos.jwt.model;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;

import lombok.Data;


@Data //getter, setter
@Entity
public class User {
	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY) // autoIncrement
	private long id;
	private String username;
	private String password;
	private String roles;
	
	public List<String> getRoleList(){
		if(this.roles.length() > 0) {
			return Arrays.asList(this.roles.split(","));
		}
		
		return new ArrayList<String>();
	}
}
