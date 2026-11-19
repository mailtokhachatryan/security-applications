package com.example.security.common;

import org.springframework.boot.persistence.autoconfigure.EntityScan;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;

@Configuration(proxyBeanMethods = false)
@ComponentScan(basePackageClasses = SharedSecurityConfiguration.class)
@EntityScan(basePackageClasses = SharedSecurityConfiguration.class)
@EnableJpaRepositories(basePackageClasses = SharedSecurityConfiguration.class)
public class SharedSecurityConfiguration {
}
