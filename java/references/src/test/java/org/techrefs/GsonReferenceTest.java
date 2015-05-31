package org.techrefs;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import lombok.Data;
import org.junit.Test;

import static org.hamcrest.CoreMatchers.*;
import static org.junit.Assert.assertThat;

public class GsonReferenceTest {
    @Test
    public void how_to_create_a_GSON_instance_with_default_config() {
        Gson gson = new Gson();
        assertThat(gson, is(notNullValue()));
    }

    @Test
    public void how_to_create_an_instance_that_can_be_configured_beyond_the_defaults(){
        /**
         * GsonBuilder is a fluent builder that can be used to configure various aspects of
         * the GSON object to meet our needs.
         */
        Gson gson = new GsonBuilder().create();
        assertThat(gson, is(notNullValue()));
    }

    @Test
    public void how_to_convert_basic_JAVA_primitives_into_JSON_objects(){
        Gson gson = new Gson();

        assertThat(gson.toJson(new String[]{"Hello", "World"}), is(equalTo("[\"Hello\",\"World\"]")));
        assertThat(gson.toJson("foo"), is(equalTo("\"foo\"")));
        assertThat(gson.toJson(1), is(equalTo("1")));
    }

    @Test
    public void how_to_convert_a_simple_POJO_into_a_JSON_object_without_using_a_type_adapter(){
        Gson gson = new Gson();
        SimplePOJOToJSON simplePOJOToJSON = new SimplePOJOToJSON();
        String json = gson.toJson(simplePOJOToJSON);

        assertThat(json, is(equalTo("{\"name\":\"Jo\",\"surname\":\"Khafaji\"}")));
    }

    @Data
    private static class SimplePOJOToJSON{
        private final String name = "Jo";
        private final String surname = "Khafaji";
        /**
         * Transient fields will not be serialized into JSON
         */
        private final transient String salary = "100000";
    }
}
