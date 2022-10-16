package com.gw2auth.oauth2.server.configuration;

import org.json.JSONException;
import org.json.JSONObject;
import org.postgresql.util.PGobject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.convert.converter.Converter;
import org.springframework.data.convert.ReadingConverter;
import org.springframework.data.convert.WritingConverter;
import org.springframework.data.jdbc.repository.config.AbstractJdbcConfiguration;
import org.springframework.stereotype.Component;

import java.sql.SQLException;
import java.util.List;

@Configuration
public class JdbcConfiguration extends AbstractJdbcConfiguration {

    private final Converter<PGobject, JSONObject> jsonReadingConverter;
    private final Converter<JSONObject, PGobject> jsonWritingConverter;

    @Autowired
    public JdbcConfiguration(Converter<PGobject, JSONObject> jsonReadingConverter, Converter<JSONObject, PGobject> jsonWritingConverter) {
        this.jsonReadingConverter = jsonReadingConverter;
        this.jsonWritingConverter = jsonWritingConverter;
    }

    @Override
    protected List<?> userConverters() {
        return List.of(this.jsonReadingConverter, this.jsonWritingConverter);
    }

    @ReadingConverter
    @Component
    public static class JSONBReadingConverter implements Converter<PGobject, JSONObject> {

        @Override
        public JSONObject convert(PGobject source) {
            if (!source.getType().equalsIgnoreCase("jsonb")) {
                throw new IllegalArgumentException("expected jsonb, got " + source.getType());
            } else if (source.getValue() == null) {
                return null;
            }

            try {
                return new JSONObject(source.getValue());
            } catch (JSONException e) {
                throw new IllegalArgumentException("expected jsonb, got invalid json", e);
            }
        }
    }

    @WritingConverter
    @Component
    public static class JSONBWritingConverter implements Converter<JSONObject, PGobject> {

        @Override
        public PGobject convert(JSONObject source) {
            final PGobject pgObject = new PGobject();
            pgObject.setType("jsonb");

            try {
                pgObject.setValue(source.toString());
            } catch (SQLException e) {
                throw new RuntimeException(e);
            }

            return pgObject;
        }
    }
}
