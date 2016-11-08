package org.techrefs;

import javaslang.control.Try;
import org.junit.Test;

public class JavaSlangRefTest {

    @Test
    public void division_by_zero_result_in_a_side_effect_in_java_in_a_form_of_an_exception(){
        int x = 5 / 0;
    }

    @Test
    public void encapsulate_a_potential_exceptionThrowing_computation_in_a_try(){
        /**
         * This will have the effect of always returning a value regardless of what
         * happens, then we can locally decide what to do on what happens.
         */
        Try<Integer> trialOfADivision = Try.of(() -> 500 / 0);

        Integer computeOrDefault = trialOfADivision.getOrElse(-1);

        System.out.println("computedOrDefault: " + computeOrDefault);

        if(trialOfADivision.isFailure()){
            System.out.println("Sending a stat message for an occurred failure:  " + trialOfADivision.getCause());
        }

        /**
         * Can we use a Try within a java for loop?
         * Well as it implements Iterable, then we surely can! It will
         * only iterate if it does have an underlying value
         */
        for(int i : trialOfADivision){
            System.out.println("for: " + i);
        }
    }

}