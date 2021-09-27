package com.gw2auth.oauth2.server.adapt;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonTypeInfo;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.Version;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonDeserializer;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.module.SimpleModule;
import org.springframework.security.jackson2.SecurityJackson2Modules;

import java.io.IOException;
import java.util.*;

public class Java9CollectionJackson2Module extends SimpleModule {

    public Java9CollectionJackson2Module() {
        super(Java9CollectionJackson2Module.class.getName(), new Version(1, 0, 0, null, null, null));
    }

    @Override
    public void setupModule(SetupContext context) {
        SecurityJackson2Modules.enableDefaultTyping(context.getOwner());
        context.setMixInAnnotations(Map.of().getClass(), MapNMixin.class);
        context.setMixInAnnotations(Set.of().getClass(), SetNMixin.class);
        context.setMixInAnnotations(List.of().getClass(), ListNMixin.class);
    }

    // region Map
    @JsonTypeInfo(use = JsonTypeInfo.Id.CLASS)
    @JsonDeserialize(using = MapNDeserializer.class)
    static abstract class MapNMixin {

        @JsonCreator
        MapNMixin(Map<?, ?> map) {
        }
    }

    static final class MapNDeserializer extends JsonDeserializer<Map<?, ?>> {

        @Override
        public Map<?, ?> deserialize(JsonParser parser, DeserializationContext context) throws IOException {
            final ObjectMapper mapper = (ObjectMapper) parser.getCodec();
            final JsonNode mapNode = mapper.readTree(parser);
            final Map<String, Object> result = new LinkedHashMap<>();

            if (mapNode != null && mapNode.isObject()) {
                final Iterator<Map.Entry<String, JsonNode>> fields = mapNode.fields();
                Map.Entry<String, JsonNode> field;

                while (fields.hasNext()) {
                    field = fields.next();
                    result.put(field.getKey(), mapper.readValue(field.getValue().traverse(mapper), Object.class));
                }
            }

            return Map.copyOf(result);
        }
    }
    // endregion

    // region Set
    @JsonTypeInfo(use = JsonTypeInfo.Id.CLASS)
    @JsonDeserialize(using = SetNDeserializer.class)
    static abstract class SetNMixin {

        @JsonCreator
        SetNMixin(Set<?> set) {
        }
    }

    static final class SetNDeserializer extends JsonDeserializer<Set<?>> {

        @Override
        public Set<?> deserialize(JsonParser parser, DeserializationContext context) throws IOException {
            final ObjectMapper mapper = (ObjectMapper) parser.getCodec();
            final JsonNode setNode = mapper.readTree(parser);
            final Set<Object> result = new LinkedHashSet<>();

            if (setNode != null && setNode.isArray()) {
                final Iterator<JsonNode> elements = setNode.elements();
                JsonNode element;

                while (elements.hasNext()) {
                    element = elements.next();
                    result.add(mapper.readValue(element.traverse(mapper), Object.class));
                }
            }

            return Set.copyOf(result);
        }
    }
    // endregion

    // region List
    @JsonTypeInfo(use = JsonTypeInfo.Id.CLASS)
    @JsonDeserialize(using = ListNDeserializer.class)
    static abstract class ListNMixin {

        @JsonCreator
        ListNMixin(List<?> list) {
        }
    }

    static final class ListNDeserializer extends JsonDeserializer<List<?>> {

        @Override
        public List<?> deserialize(JsonParser parser, DeserializationContext context) throws IOException {
            final ObjectMapper mapper = (ObjectMapper) parser.getCodec();
            final JsonNode listNode = mapper.readTree(parser);
            final List<Object> result = new ArrayList<>();

            if (listNode != null && listNode.isArray()) {
                final Iterator<JsonNode> elements = listNode.elements();
                JsonNode element;

                while (elements.hasNext()) {
                    element = elements.next();
                    result.add(mapper.readValue(element.traverse(mapper), Object.class));
                }
            }

            return List.copyOf(result);
        }
    }
    // endregion
}
