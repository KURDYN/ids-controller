package com.ids.ids_controller;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableScheduling;

@EnableScheduling
@SpringBootApplication
public class IdsControllerApplication {

	public static void main(String[] args) {
		SpringApplication.run(IdsControllerApplication.class, args);
	}

}
