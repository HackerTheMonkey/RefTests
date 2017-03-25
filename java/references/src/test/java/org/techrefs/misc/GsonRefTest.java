package org.techrefs.misc;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.InstanceCreator;
import lombok.Data;
import org.junit.Test;
import org.techrefs.gson.AClassWithoutZeroArgConstructor;
import org.techrefs.gson.Id;

import java.lang.reflect.Type;

import static org.hamcrest.CoreMatchers.*;
import static org.junit.Assert.assertThat;

public class GsonRefTest {
    @Test
    public void how_to_create_a_GSON_instance_with_default_config() {
        Gson gson = new Gson();
        assertThat(gson, is(notNullValue()));
    }

    @Test
    public void how_to_create_an_instance_that_can_be_configured_beyond_the_defaults() {
        /**
         * GsonBuilder is a fluent builder that can be used to configure various aspects of
         * the GSON object to meet our needs.
         */
        Gson gson = new GsonBuilder().create();
        assertThat(gson, is(notNullValue()));
    }

    @Test
    public void how_to_convert_basic_JAVA_primitives_into_JSON_objects() {
        Gson gson = new Gson();

        assertThat(gson.toJson(new String[]{"Hello", "World"}), is(equalTo("[\"Hello\",\"World\"]")));
        assertThat(gson.toJson("foo"), is(equalTo("\"foo\"")));
        assertThat(gson.toJson(1), is(equalTo("1")));
    }

    @Test
    public void how_to_convert_a_simple_POJO_into_a_JSON_object_without_using_a_type_adapter() {
        Gson gson = new Gson();
        SimplePOJO simplePOJO = new SimplePOJO();
        String json = gson.toJson(simplePOJO);

        /**
         * Notice that transient fields are not included in the serialization/deserialization process.
         */
        assertThat(json, is(equalTo("{\"name\":\"Jo\",\"surname\":\"Khafaji\"}")));
    }

    @Test
    public void Gson_can_serialize_and_deserialize_static_inner_classes() {
        Gson gson = new Gson();

        /**
         * Let's serialize a static inner class to JSON
         */
        B.StaticInnerClass staticInnerClass = new B.StaticInnerClass();
        String serializedStaticInnerClass = gson.toJson(staticInnerClass);

        assertThat(serializedStaticInnerClass, is(equalTo("{\"foo\":\"foo\"}")));

        /**
         * We can deserialize it back to JSON as well, hassle free.
         */
        B.StaticInnerClass deSerializedStaticInnerClass = gson.fromJson(serializedStaticInnerClass, B.StaticInnerClass.class);

        assertThat(deSerializedStaticInnerClass, is(notNullValue()));
        assertThat(deSerializedStaticInnerClass.getFoo(), is(equalTo("foo")));
    }

    @Test
    public void Gson_can_serialize_and_deserialize_an_instance_bound_inner_classes() {
        Gson gson = new Gson();

        /**
         * Let's serialize an instance-bound inner class to JSON
         */
        A.InstanceBoundInnerClass innerClass = new A().new InstanceBoundInnerClass();
        String serializedInnerClass = gson.toJson(innerClass);

        assertThat(serializedInnerClass, is(equalTo("{\"foo\":\"foo\"}")));

        /**
         * We can deserialize it back to JSON as well, hassle free.
         */
        A.InstanceBoundInnerClass deSerializedInnerClass = gson.fromJson(serializedInnerClass, A.InstanceBoundInnerClass.class);
        System.out.println(deSerializedInnerClass);
        assertThat(deSerializedInnerClass, is(notNullValue()));
        assertThat(deSerializedInnerClass.getFoo(), is(equalTo("foo")));
    }


    @Test(expected = UnsupportedOperationException.class)
    public void Gson_will_throw_an_UnsupportedOperationException_if_it_cant_instantiate_a_class_for_whatever_reason() {
        /**
         * The documentation says that GSON can't instantiate a clas without a zero-argument constructor, but
         * that's not always the case.
         */
        Gson gson = new Gson();
        gson.toJson(new Id<String>(String.class, 1l));
    }
    
    @Test
    public void Gson_seem_to_be_able_to_serialize_deserialize_some_classes_that_dont_have_zero_argument_contstructors() {
        new Gson().toJson(new AClassWithoutZeroArgConstructor("foo", 1l));
    }

    @Test
    public void we_can_use_an_InstanceCreator_for_classes_that_GSON_cant_easily_instantiate_for_serialization_and_deserialization() {
        /**
         * TODO
         * Fix this, not WORKING
         */

        /**
         * This might be needed for classes that either we don't want or
         * can't modify to enable GSON to instantiate them.
         */
        Gson gson = new GsonBuilder().
                registerTypeAdapter(Id.class, new FooInstanceCreator()).
                create();

        /**
         * Let's serialize it to JSON
         */
        String jsonString = gson.toJson(new FooInstanceCreator().createInstance(Id.class));
        System.out.println(jsonString);
    }


    /**
     * TODO
     * Move these classes into appropriate packages as top-level classes unless
     * we need them to be inner classes for testing purposes.
     */

    private static class FooInstanceCreator implements InstanceCreator<Id>{

        @Override
        public Id createInstance(Type type) {
            return new Id(String.class, 100L);
        }
    }

    @Data
    private static class SimplePOJO {
        private final String name = "Jo";
        private final String surname = "Khafaji";
        /**
         * Transient fields will not be serialized into JSON
         */
        private final transient String salary = "100000";
    }

    @Data
    private static class A {
        private String a;

        @Data
        private class InstanceBoundInnerClass {
            private String foo = "foo";

        }
    }

    @Data
    public static class B {
        private String b;

        @Data
        private static class StaticInnerClass {
            private String foo = "foo";
        }
    }


}
