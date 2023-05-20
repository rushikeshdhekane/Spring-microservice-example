package com.rbrains.photoapp.api.users.ui.controllers;

import javax.validation.Valid;

import org.modelmapper.ModelMapper;
import org.modelmapper.convention.MatchingStrategies;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.rbrains.photoapp.api.users.service.UsersService;
import com.rbrains.photoapp.api.users.shared.UserDto;
import com.rbrains.photoapp.api.users.ui.model.CreateUserRequestModel;
import com.rbrains.photoapp.api.users.ui.model.CreateUserResponseModel;

@RestController
@RequestMapping("/users")
public class UsersController {

	@Autowired
	private Environment env;
	
	@Autowired
	private UsersService userService;
	
	@GetMapping("/status/check")
	public String status() {
		return "working on port "+env.getProperty("local.server.port");
	}
	
	@PostMapping
	public ResponseEntity createUser(@Valid @RequestBody CreateUserRequestModel userDetails) {
		
		ModelMapper modelMapper = new ModelMapper();
		modelMapper.getConfiguration().setMatchingStrategy(MatchingStrategies.STRICT);
		
		UserDto userDto = modelMapper.map(userDetails, UserDto.class);
		UserDto createUser = userService.createUser(userDto);
		
		CreateUserResponseModel returnValue = modelMapper.map(createUser, CreateUserResponseModel.class);
		
		return ResponseEntity.status(HttpStatus.CREATED).body(returnValue);
	}
}
