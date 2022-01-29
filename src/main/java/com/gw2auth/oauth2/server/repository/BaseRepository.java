package com.gw2auth.oauth2.server.repository;

import org.springframework.data.repository.NoRepositoryBean;
import org.springframework.data.repository.Repository;

@NoRepositoryBean
public interface BaseRepository<T> extends Repository<T, Void> {

    T save(T entity);
}
