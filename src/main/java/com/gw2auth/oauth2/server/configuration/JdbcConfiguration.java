package com.gw2auth.oauth2.server.configuration;

import org.json.JSONException;
import org.json.JSONObject;
import org.postgresql.util.PGobject;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.convert.converter.Converter;
import org.springframework.data.convert.ReadingConverter;
import org.springframework.data.convert.WritingConverter;
import org.springframework.data.jdbc.repository.config.AbstractJdbcConfiguration;

import java.sql.SQLException;
import java.util.List;

@Configuration
public class JdbcConfiguration extends AbstractJdbcConfiguration {

    @Override
    protected List<?> userConverters() {
        return List.of(new JSONBReadingConverter(), new JSONBWritingConverter());
    }

    @ReadingConverter
    private static class JSONBReadingConverter implements Converter<PGobject, JSONObject> {

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
    private static class JSONBWritingConverter implements Converter<JSONObject, PGobject> {

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
