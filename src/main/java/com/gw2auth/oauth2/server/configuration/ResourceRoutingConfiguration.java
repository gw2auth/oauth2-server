package com.gw2auth.oauth2.server.configuration;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.Resource;
import org.springframework.web.servlet.config.annotation.ResourceHandlerRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;
import org.springframework.web.servlet.resource.PathResourceResolver;

import java.io.IOException;

@Configuration
public class ResourceRoutingConfiguration implements WebMvcConfigurer {

    private final boolean useCache;

    @Autowired
    public ResourceRoutingConfiguration(@Value("${spring.thymeleaf.cache:false}") boolean useCache) {
        this.useCache = useCache;
    }

    @Override
    public void addResourceHandlers(ResourceHandlerRegistry registry) {
        registry.addResourceHandler("/**")
                .addResourceLocations("classpath:/static/")
                .resourceChain(this.useCache)
                .addResolver(new PathResourceResolver() {
                    @Override
                    protected Resource getResource(String resourcePath, Resource location) throws IOException {
                        Resource resource = super.getResource(resourcePath, location);

                        if (resource == null) {
                            resource = super.getResource("/index.html", location);
                        }

                        return resource;
                    }
                });
    }
}
