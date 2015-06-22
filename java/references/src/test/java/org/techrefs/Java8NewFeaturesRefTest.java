package org.techrefs;

import lombok.Builder;
import lombok.Data;
import org.junit.Test;

import java.util.Arrays;
import java.util.List;
import java.util.stream.DoubleStream;
import java.util.stream.IntStream;
import java.util.stream.Stream;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.MatcherAssert.assertThat;

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
    public void we_dont_have_to_create_collections_to_obtain_a_stream() {
        Stream.of(
                Person.builder().age(10).name("Alice"),
                Person.builder().age(29).name("Bob"))
                .findFirst().ifPresent(System.out::println);
    }

    @Test
    public void we_can_replace_for_loops_with_primitive_int_streams_pretty_cool_init() {
        IntStream.range(0, 5).forEach(item -> {
            assertThat(item, is(notNullValue()));
            System.out.println(item);
        });
    }

    @Test
    public void primitive_IntStreams_supports_average_terminal_operation_too() {
        IntStream.range(0, 5).average().ifPresent(System.out::println);
    }

    @Test
    public void primitive_IntStreams_supports_sum_terminal_operation_too() {
        double sum = DoubleStream.builder().add(1.0).add(2.9).build().sum();
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

    @Data
    @Builder
    private static class Person {
        private String name;
        private int age;
    }
}
