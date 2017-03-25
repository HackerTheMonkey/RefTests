package org.techrefs.java8InAction;

import lombok.Builder;
import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import org.junit.Test;

import java.io.File;
import java.io.FileFilter;
import java.util.Arrays;
import java.util.List;
import java.util.function.Function;
import java.util.stream.DoubleStream;
import java.util.stream.IntStream;
import java.util.stream.Stream;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.MatcherAssert.assertThat;

@Slf4j
public class Java8NewFeaturesRefTest {

    private List<String> someListOfStuff = Arrays.asList("a1", "a2", "b1", "c2", "c1");

    @Test
    public void print_out_all_items_that_start_with_c_and_convert_them_to_UPPERCASE() {
        someListOfStuff.
                stream().
                    filter(item -> item.startsWith("c")).
                    map(String::toUpperCase).
                    sorted().
                forEach(System.out::println);
    }

    @Test
    public void find_the_first_element_in_the_list_and_print_it_out() {
        someListOfStuff.
                stream().
                findFirst().
                ifPresent(System.out::println);
    }

    @Test
    public void we_do_not_have_to_create_collections_to_obtain_a_stream() {
        Stream.of(
                Person.builder().age(10).name("Alice"),
                Person.builder().age(29).name("Bob"))
                .findFirst().ifPresent(System.out::println);
    }

    @Test
    public void we_can_replace_for_loops_with_primitive_int_streams() {
        IntStream.range(0, 5).forEach(item -> {
            assertThat(item, is(notNullValue()));
            log.info("item: " + item);
        });
    }

    @Test
    public void primitive_IntStreams_supports_average_terminal_operation_too() {
        IntStream.range(0, 5).average().ifPresent(System.out::println);
    }

    @Test
    public void primitive_DoubleStreams_supports_sum_terminal_operation_too() {
        double sum = DoubleStream
                .builder()
                    .add(1.0)
                    .add(2.9)
                .build()
                .sum();
        System.out.println(sum);
    }

    @Test
    public void lets_take_a_regular_stream_and_convert_it_into_a_primitive_stream() {
        someListOfStuff.
                stream().
                    map(item -> item.substring(1)).
                    mapToInt(Integer::parseInt).
                    max().
                ifPresent(System.out::println);
    }

    @Test
    public void IntStream_contains_a_builder(){
        IntStream intStream = IntStream.builder()
                .add(1)
                .add(2)
                .build();
        intStream.forEach(System.out::println);
    }

    @Test
    public void behaviour_parameterization_and_considering_methods_as_firstClassCitizens(){
        /**
         * - You can use an anonymous inner class
         * - You can use a method reference to:
         *      - a method that accepts a file and return a boolean
         *      - a method on a File object that returns a boolean and that it accept no parameters
         * - A Lambda
         */
        // Using an anonymous inner class, like the old days.
        File[] files2 = new File(".").listFiles(file -> file.isHidden());
        System.out.println("Via an anonymous inner class");
        Arrays.asList(files2).forEach(System.out::println);

        // using a method reference to a method on a file object
        File[] files3 = new File(".").listFiles(File::isHidden);
        System.out.println("using a method reference to a method on a file object");
        Arrays.asList(files3).forEach(System.out::println);

        // using a method reference to a method that accepts a file and returns a boolean
        File[] file4 = new File(".").listFiles(this::isHidden);
        System.out.println("using a method reference to a method that accepts a file and returns a boolean");
        Arrays.asList(file4).forEach(System.out::println);

        // Using an anonymous lambda
        File[] file5 = new File(".").listFiles(file -> file.isHidden());
        System.out.println("using a lambda");
        Arrays.asList(file5).forEach(System.out::println);

        // Using a named lambda, not so much.
        // this tells us that functions and lambda's are a bit different in Java
        File[] file6 = new File(".").listFiles(file -> isFileHidden().apply(file));
        System.out.println("using a lambda");
        Arrays.asList(file6).forEach(System.out::println);

        // Also we can use a method that returns an instance of a functional
        // interface (one that has a single method), and that that functional interface
        // is realized vis a lambda expression
        File[] file7 = new File(".").listFiles(createAFileFilter());
        System.out.println("a FunctionalInterface implemented via a lambda");
        Arrays.asList(file7).forEach(System.out::println);
    }

    @Test
    public void create_an_instance_of_a_functional_interface(){
        SomeInterface someInterfaceViaLambda = (something) -> System.out.println(something);
        someInterfaceViaLambda.doOneThing("lambda's for functional interfaces in action");

        // any method/function that matches our signature will do
        SomeInterface someInterfaceViaMethodReference = System.out::println;
        someInterfaceViaMethodReference.doOneThing("Method references for FunctionalInterfaces in action");

        SomeInterface someInterfaceViaConstructorReference = UseThisToCreateFunctionalInterface::new;
        someInterfaceViaConstructorReference.doOneThing("Constructor References for FunctionalInterfaces in action");
    }


    private static class UseThisToCreateFunctionalInterface{
        private final String name;
        public UseThisToCreateFunctionalInterface(String name) {
            this.name = name;
            System.out.println(this.name);
        }
    }

    private FileFilter createAFileFilter() {
        // The type of "file" is inferred here to be File
        // as well as the return type
        return file -> file.isHidden();
    }

    private Function<File, Boolean> isFileHidden(){
        return (file) -> file.isHidden();
    }

    private boolean isHidden(File file){
        return file.isHidden();
    }

    @Data
    @Builder
    private static class Person {
        private String name;
        private int age;
    }



    @FunctionalInterface
    private interface SomeInterface{
        void doOneThing(String something);
    }
}
