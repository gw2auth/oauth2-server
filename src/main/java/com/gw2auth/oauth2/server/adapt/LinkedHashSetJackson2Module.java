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

public class LinkedHashSetJackson2Module extends SimpleModule {

    public LinkedHashSetJackson2Module() {
        super(LinkedHashSetJackson2Module.class.getName(), new Version(1, 0, 0, null, null, null));
    }

    @Override
    public void setupModule(SetupContext context) {
        SecurityJackson2Modules.enableDefaultTyping(context.getOwner());
        context.setMixInAnnotations(LinkedHashSet.class, LinkedHashSetMixIn.class);
    }

    // region Set
    @JsonTypeInfo(use = JsonTypeInfo.Id.CLASS)
    @JsonDeserialize(using = LinkedHashSetDeserializer.class)
    static abstract class LinkedHashSetMixIn {

        @JsonCreator
        LinkedHashSetMixIn(Set<?> set) {
        }
    }

    static final class LinkedHashSetDeserializer extends JsonDeserializer<Set<?>> {

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

            return result;
        }
    }
    // endregion
}
