package com.gw2auth.oauth2.server.repository;

import org.springframework.data.repository.NoRepositoryBean;
import org.springframework.data.repository.Repository;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

@NoRepositoryBean
public interface BaseRepository<T> extends Repository<T, Void> {

    T save(T entity);

    @Transactional
    default List<T> saveAll(Collection<T> entities) {
        final List<T> results = new ArrayList<>(entities.size());

        for (T entity : entities) {
            results.add(save(entity));
        }

        return results;
    }
}
