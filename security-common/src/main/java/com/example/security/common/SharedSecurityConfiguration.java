package com.example.security.common;

import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;

@Configuration(proxyBeanMethods = false)
@ComponentScan(basePackageClasses = SharedSecurityConfiguration.class)
public class SharedSecurityConfiguration {
}
