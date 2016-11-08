package org.techrefs;

import lombok.Builder;
import lombok.Data;
import org.hamcrest.Description;
import org.hamcrest.Matcher;
import org.hamcrest.MatcherAssert;
import org.hamcrest.TypeSafeMatcher;
import org.junit.Ignore;
import org.junit.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.InOrder;
import org.mockito.Mockito;
import org.mockito.exceptions.misusing.UnfinishedVerificationException;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;

import java.util.*;

import static org.hamcrest.CoreMatchers.*;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.text.IsEmptyString.isEmptyString;
import static org.mockito.BDDMockito.given;
import static org.mockito.Matchers.any;
import static org.mockito.Mockito.*;

public class MockitoRefTest {

    @Test
    public void verify_that_calls_to_a_mocked_object_have_actually_happened() {
        /**
         * Create a mock list
         */
        List mockList = mock(List.class);

        /**
         * Invoke methods on the created mock
         */
        mockList.add("One");
        mockList.clear();

        /**
         * Verify that the previous two calls have actually happened.
         */
        verify(mockList).add("One");
        verify(mockList, times(1)).add("One");//times(1) is the default behaviour and can actually be ommitted.
        verify(mockList).clear();
        verify(mockList, never()).add("Two"); // never() is an alias for times(0)
    }

    @Test
    public void it(){
        List mockList = mock(List.class);

        when(mockList.get(0)).thenReturn(1).thenThrow(IllegalFormatException.class);

        assertThat(mockList.get(0), is(1));
        mockList.get(0);
    }

    @Test(expected = RuntimeException.class)
    public void lets_do_some_basic_stubbing() {
        /**
         * Create the mocked object
         */
        LinkedList linkedList = mock(LinkedList.class);

        /**
         * Let's do some partial behaviour specificatios, i.e. stubbing.
         */
        when(linkedList.get(0)).thenReturn("first");
        when(linkedList.get(1)).thenThrow(RuntimeException.class);

        /**
         * Let's do some invocations against the mocked object
         * and see what happens.
         */
        MatcherAssert.assertThat((String) linkedList.get(0), is(equalTo("first")));
        linkedList.get(1);
        assertThat(linkedList.get(999), is(nullValue()));
        /**
         * We can verify the stubbed invocations, but that is not absolutely
         * needed as if our application cares about a partiuclar stubbed behaviour, then not specifying that
         * should result in the fact that the application would blow up elsewhere.
         */
        verify(linkedList).get(0);
        verify(linkedList).get(1);
        verify(linkedList).get(999);
        verify(linkedList, never()).get(100);
    }

    @Test
    public void last_stubbing_always_win() {
        /**
         * With literal argument values
         */
        Map map01 = mock(Map.class);

        when(map01.get("Foo")).thenReturn("Bar");
        when(map01.get("Foo")).thenReturn("I don't know it!");

        assertThat((String) map01.get("Foo"), is(not(equalTo("Bar"))));

        /**
         * With argument matchers
         */
        Map map = mock(Map.class);

        when(map.get(anyString())).thenReturn("Bar");
        when(map.get(anyString())).thenReturn("I don't know it!");

        assertThat((String) map.get("Foo"), is(not(equalTo("Bar"))));

        /**
         * even when mixing argument matchers and literal Strings
         */
        Map yetAnotherMap = mock(Map.class);

        when(yetAnotherMap.get(anyString())).thenReturn("Bar");
        when(yetAnotherMap.get(anyString())).thenReturn("I don't know it!");

        assertThat((String) yetAnotherMap.get("Foo"), is(not(equalTo("Bar"))));
    }


    @Test
    public void stubbing_using_mockito_builtin_agrument_matchers_sameAppliesOnVerification() {
        /**
         * The built-in argument matchers are in the form of anyX()
         */
        List list = mock(List.class);

        when(list.contains(anyInt())).thenReturn(true);

        assertThat(list.contains(111), is(true));
    }

    @Test
    public void stubbing_using_natural_equals_java_style_thePreferredWay_sameAppliesOnVerification() {
        List list = mock(List.class);

        when(list.contains("something")).thenReturn(true);

        assertThat(list.contains("something"), is(true));
    }

    @Test
    public void stubbing_using_custom_hamcrest_matchers_sameAppliesOnVerification() {
        List list = mock(List.class);

        when(list.contains(argThat(isValid()))).thenReturn(true);

        assertThat(list.contains(111), is(false));
        assertThat(list.contains("HELLO"), is(true));
    }

    @Test
    public void when_using_argument_matchers_then_all_arguments_have_to_be_matchers_weather_stubbing_or_mocking() {
        MultipleArgumentMatchersExample mock = mock(MultipleArgumentMatchersExample.class);

        when(mock.someMethodWithMultipleArguments(anyInt(), anyInt(), anyBoolean(), anyString())).thenReturn("Yo");

        assertThat(mock.someMethodWithMultipleArguments(1, 1, false, "Hey"), is(equalTo("Yo")));

        verify(mock, atLeast(1)).someMethodWithMultipleArguments(anyInt(), anyInt(), anyBoolean(), anyString());

        /**
         * The code below will not work as we are using a literal boolean while we should be using argument
         * matchers everywhere during the verification call.
         */
        //verify(mock, atLeast(1)).someMethodWithMultipleArguments(anyInt(), anyInt(), true, anyString());
    }

    /**
     * For stubbing void methods, we have to use a slightly different syntax which conforms to the doX family
     * of methods. This is all because we need to satisfy the Java compiler.
     */
    @Test(expected = RuntimeException.class)
    public void stubbing_void_methods() {
        LinkedList<String> linkedList = mock(LinkedList.class);
        /**
         * The doX() family of methods can potentially be used in all stubbing
         * cases. It sounds more expressive as well.
         *
         * Here are a few usage examples with not only void methods.
         */

        /**
         * Notice that the method invocation on the mock can happen
         * inside the bracket when it returns a value. If it's a void,
         * then it has to happen outside the bracket to satisfy the Java
         * compiler. As a practise, we could always do the mock invocation
         * while stubbing/verifying outside the brackets.
         */
        doThrow(RuntimeException.class).when(linkedList).clear();
        doNothing().when(linkedList.add("doNothing"));
        doCallRealMethod().when(linkedList).add("callRealMethod");

        doAnswer(new Answer() {
            @Override
            public String answer(InvocationOnMock invocationOnMock) throws Throwable {
                return "Bar";
            }
        }).when(linkedList).getLast();

        doReturn("Foo").when(linkedList).getFirst();

        linkedList.clear();
        assertThat(linkedList.add("doNothing"), is(false));
        assertThat(linkedList.add("callRealMethod"), is(true));
        assertThat(linkedList.getLast(), is(equalTo("Bar")));
        assertThat(linkedList.getFirst(), is(equalTo("Foo")));
    }

    @Test
    public void in_order_verification_for_calls_on_a_single_mock_object() {
        LinkedList linkedList = mock(LinkedList.class);

        linkedList.add("Add this first");
        linkedList.add("Add this second");

        /**
         * Uncommenting this should fail the test as we have specified that no further
         * interaction with the mock object should happen beyond the ordered list of interactions
         * that we have verified.
         */
//        linkedList.add("Third");

        /**
         * Now we need to create an InOrder verifier to verify that
         * certain method calls to our mocked object have happened in
         * the desired order.
         */
        InOrder inOrder = inOrder(linkedList);

        inOrder.verify(linkedList).add("Add this first");
        inOrder.verify(linkedList).add("Add this second");

        inOrder.verifyNoMoreInteractions();
    }

    @Test
    public void lets_do_inOrder_verification_on_multiple_mocks() {
        List firstList = mock(List.class);
        List secondList = mock(List.class);

        firstList.add("first");
        secondList.add("second");

        /**
         * The verified don't care about further interactions with
         * the mock object if these were not specified during the
         * verification or that we have explicitly specified that nothing
         * should be called on the mock object apart from the verified invocations, e.g.
         * when using inOrder.verifyNoMoreInteractions();
         */
        firstList.addAll(Collections.emptyList());


        InOrder inOrder = inOrder(firstList, secondList);

        inOrder.verify(firstList).add(anyString());
        inOrder.verify(secondList).add(anyString());
    }

    @Test
    public void we_can_also_make_sure_that_calls_never_happened_on_mocks() {
        List mock1 = mock(List.class);
        List mock2 = mock(List.class);
        List mock3 = mock(List.class);

        mock1.add("1");

        /**
         * Ordinary verificaiton
         */
        verify(mock1, times(1)).add(anyString());

        /**
         * We can also verify that certain method calls never happened on
         * our mock object
         */
        verify(mock1, never()).add("2");
        /**
         * We can also verify that there were no interactions whatsoever
         * with the rest of the mocks.
         */
        verifyZeroInteractions(mock2, mock3);
    }

    @Test
    public void there_is_a_way_to_find_out_if_there_is_any_redundant_mock_invocations_that_we_didnt_know_we_were_making() {
        List mock01 = mock(List.class);
        List mock02 = mock(List.class);

        mock01.add("1");
        mock02.add("2");
        /**
         * Uncommenting the following line would result in a test failure as this statement represents an interaction
         * with the mock object other than what we are verifying.
         */
//        mock01.add("3");

        verify(mock01).add("1");
        verify(mock02).add("2");

        verifyNoMoreInteractions(mock01, mock02);
    }

    @Test
    public void generic_classes_can_be_mocked_in_this_way() {
        /**
         * Simply the mock variable type need to refer to the
         * exact types that we need and we get a generic mock.
         */
        Map<String, String> genericMap = mock(Map.class);

        genericMap.put("key", "value");
    }

    @Test(expected = RuntimeException.class)
    public void we_can_stub_multiple_method_calls_as_well() {
        List<String> firstList = mock(List.class);
        List<Long> secondList = mock(List.class);

        when(firstList.get(0)).thenReturn("1", "2", "3");
        when(secondList.get(0)).thenReturn(2L).thenThrow(RuntimeException.class);


        assertThat(firstList.get(0), is(equalTo("1")));
        assertThat(firstList.get(0), is(equalTo("2")));
        assertThat(firstList.get(0), is(equalTo("3")));


        /**
         * Last stub always win
         */
        assertThat(firstList.get(0), is(equalTo("3")));

        assertThat(secondList.get(0), is(equalTo(2L)));
        secondList.get(0);
    }

    @Test
    public void dynammic_stubbing_this_is_an_advanced_but_less_recommended_way_of_stubbing_with_call_backs() {
        List<String> mockList = mock(ArrayList.class);

        when(mockList.get(1)).thenReturn("Foo");

        when(mockList.get(0)).then(new Answer<String>() {
            @Override
            public String answer(InvocationOnMock invocationOnMock) throws Throwable {
                /**
                 * We can have access to the arguments that the stubbed method has
                 * been called with.
                 */
                System.out.println("Arguments: " + Arrays.asList(invocationOnMock.getArguments()));
                ;

                /**
                 * We can also invoke the real method rather than the mock version of it.
                 *
                 * Uncommentig the below line would result in an exception to be thrown as
                 * there are no elements in the underlying array.
                 */
//                System.out.println("Real method returns: " + invocationOnMock.callRealMethod());

                /**
                 * We can even retrieve an instance of the mock object and call a totally
                 * different stubbed methods on it.
                 */
                System.out.println("Calling another stubbed method: " + ((List<String>) invocationOnMock.getMock()).get(1));

                /**
                 * We can return whatever we want.
                 */
                return "Bar";
            }
        });

        assertThat(mockList.get(0), is(equalTo("Bar")));
    }

    @Test
    public void we_can_also_do_partial_mocking_using_spys_non_stubbed_calls_will_invoke_real_methods() {

        /**
         * Partial mocks can be used as a refactoring technique as a replacement
         * for the subclass-and-override when dealing with legacy code.
         *
         * Reference: http://monkeyisland.pl/2009/01/13/subclass-and-override-vs-partial-mocking-vs-refactoring/
         */

        ArrayList<String> arrayList = new ArrayList<String>();
        ArrayList<String> arrayListSpy = spy(arrayList);

        /**
         * Let's do some stubbing. This is why spying is termed also as
         * partial mocking as it allows you to mock certain parts of an "object"
         * but not others.
         */
        when(arrayListSpy.size()).thenReturn(100);

        /**
         * Invoking non-stubbed methods would result in calling the real methods
         * on the object being spyed on.
         */
        arrayListSpy.add("one");
        arrayListSpy.add("two");

        assertThat(arrayListSpy.get(0), is(equalTo("one")));
        assertThat(arrayListSpy.get(1), is(equalTo("two")));

        /**
         * Calling a stubbed method works as expected.
         */
        assertThat(arrayListSpy.size(), is(equalTo(100)));

        /**
         * The interesting thing is that we can verify both
         * stubbed and real method invocations.
         */
        verify(arrayListSpy).size();
        verify(arrayListSpy, times(2)).add(anyString());
        verify(arrayListSpy, times(2)).get(anyInt());
    }

    @Test
    public void sometimes_we_have_to_use_doX_family_of_methods_when_stubbing_spies() {
        ArrayList<String> arrayList = new ArrayList<String>();
        ArrayList<String> spy = spy(arrayList);

        /**
         * As the non-stubbed methods calls would result in invoking the real method
         * on the object being spyed on, then the following call will throw an
         * IndexOutOfBoundsException as the arrayList has no elements at this point
         * in time.
         */
        //when(spy.get(0)).thenReturn("one");

        /**
         * Instead, and in order to stub methods against spys we have to use the
         * doX() family of methods, such as:
         */
        doReturn("one").when(spy).get(0);

        assertThat(spy.get(0), is(equalTo("one")));
    }

    @Test
    public void when_spying_mockito_creates_a_copy_of_the_instance_being_spied_on() {
        ArrayList<String> arrayList = new ArrayList<String>();
        ArrayList<String> spy = spy(arrayList);

        /**
         * Let's change the state of the real instance by interacting
         * directly with it.
         */
        arrayList.add("one");

        /**
         * As mockito creates a new copy (i.e. clone) the real instance when
         * we create the spy, then any interaction with non-stubbed method would
         * result in calling methods on the clone of the real instance rather than
         * the original instance being spied on. Conclusion is, interacting with non-stubbed
         * methods will not change the state of the real original instance but rather it will
         * change the state of the cloned instance.
         */
        spy.add("one");
        spy.remove(0);

        assertThat(arrayList.get(0), is(notNullValue()));
    }

    @Test
    public void we_cant_stub_final_methods_on_a_spy_the_stubbing_will_have_no_effect() {


        AClassWithFinalMethod aClassWithFinalMethod = new AClassWithFinalMethod();
        AClassWithFinalMethod spy = spy(aClassWithFinalMethod);

        /**
         * Notice that Mockito keeps quite about this and it will simply call
         * the real methods the next time we interact with the spy ignoring the fact
         * that we have explicitly stubbed that method.
         */

        /**
         * On a different note, simply attempting to stub a final method on
         * a spy object seems to mess up the state of completely unrelated
         * tests.
         *
         * Try uncommenting the below line and re-run all the tests in this
         * class and see if they are passing. The strange thing is, this unit test
         * passes on its own, but not when you run it alongside other tests.
         */
//        doReturn("Bar").when(spy).testMethod();

        assertThat(spy.testMethod(), is(equalTo("Foo")));

        /**
         * We can't even verify final methods on a spy, big time.
         */
//        verify(spy, times(1)).testMethod();
    }

    @Test(expected = IndexOutOfBoundsException.class)
    public void partial_mocking_can_be_selectively_enabled_on_mocks_without_the_need_to_use_spies(){

        /**
         * Create a mock in the usual way we do
         */
        List<String> mockList = mock(ArrayList.class);

        /**
         * then stub some method call
         */
        when(mockList.size()).thenReturn(10);
        /**
         * Imagine that we need to enable partial mocking to
         * call some real method on our mocked object, then we
         * can do that without the need to use a spy.
         */
        when(mockList.get(0)).thenCallRealMethod();

        /**
         * Do the needed invocations.
         */
        assertThat(mockList.size(), is(10));
        mockList.get(0);
    }

    @Test
    public void we_can_change_the_default_return_type_of_non_stubbed_methods_by_using_SmartNulls_Strategy() {
        /**
         * In traditional mocks, for any non-primitive return type of an unstubbed method a null will
         * be returned instead. We can change the default return type by altering the default strategy
         * that Mockito operates with.
         *
         * NOTE: The SMART NULLs strategy will be the default strategy in the upcoming version
         * of Mockito, e.g. Mockito 2.0
         */
        List mockThatReturnsSmartNulls = mock(List.class, Mockito.RETURNS_SMART_NULLS);
        List traditionalMockThatReturnsNulls = mock(List.class);

        assertThat(mockThatReturnsSmartNulls.get(0), is(notNullValue()));
        assertThat(traditionalMockThatReturnsNulls.get(0), is(nullValue()));
    }

    @Test
    public void we_can_also_override_the_default_unstubbed_methods_return_values_with_our_custom_implementation() {
        List<String> aTraditionalMock = mock(List.class);

        List<String> aMockThatReturnsCustomizedDefaultValue = mock(List.class, new Answer() {
            @Override
            public String answer(InvocationOnMock invocation) throws Throwable {
                return "";
            }
        });

        /**
         * Interesting gotcha, stubbing a method on a mock that have a customized
         * return values could potentially fail if we haven't taken that method
         * return type into consideration.
         *
         * E.g uncommenting the following method call would fail as the unstubbed
         * version of the method will be called first and it will return a String
         * as per our return-value customization, hence we end up with a ClassCastException.
         *
         * Solution to this is to stub with the dox() family of methods instead of
         * the traditional stubbing style.
         */
        //when(aMockThatReturnsCustomizedDefaultValue.size()).thenReturn(100);
        doReturn(100).when(aMockThatReturnsCustomizedDefaultValue).size();

        assertThat(aTraditionalMock.size(), is(equalTo(0)));
        assertThat(aMockThatReturnsCustomizedDefaultValue.size(), is(equalTo(100)));

        assertThat(aMockThatReturnsCustomizedDefaultValue.get(0), is(isEmptyString()));
    }

    @Test
    public void we_can_verify_mock_methods_invocations_with_certain_arguments_via_an_ArgumentCaptor() {

        /**
         * Create an ArgumentCaptor that would potentially capture arguments passed to mocks
         * that are of the type Person. Note that Person is the type of teh argument that
         * we would like to capture.
         */
        ArgumentCaptor<Person> personArgumentCaptor = ArgumentCaptor.forClass(Person.class);
        PersonProcessor personProcessor = mock(PersonProcessor.class);

        Person person = Person.builder().name("Foo").build();
        personProcessor.processPerson(person);

        /**
         * Let's verify that the processPerson() method has been invoked
         * on the mock. Then capture the argument that the method has been
         * called with for further verification
         */
        verify(personProcessor).processPerson(personArgumentCaptor.capture());
        /**
         * Now we have the actual argument that the mocked method has been called
         * with, then we can do a little bit of further assertion on it.
         */
        assertThat(personArgumentCaptor.getValue().getName(), is(equalTo("Foo")));

        /**
         * This style is different than the verfication of mocks invocations
         * using argument matchers in that the argument verification happens
         * after the mocked operation verification while it happens at the same
         * time when we use argument matchers/equals e.g.
         */
        verify(personProcessor, times(1)).processPerson(person);
        verify(personProcessor, times(1)).processPerson(any(Person.class));
    }

    @Test
    public void we_can_also_do_some_stubbing_with_an_argument_captor(){
        /**
         * Create an ArgumentCaptor of for the Person class
         */
        ArgumentCaptor<Person> personArgumentCaptor = ArgumentCaptor.forClass(Person.class);

        /**
         * Stub the mock PersonProcessor passing in an ArgumentCaptor so we can later verify
         * on what have been passed to invoke the stubbed method.
         *
         * Note: According to Mockito documentation, custom argument matchers are better suited
         * when stubbing than using Argument Captors.
         */
        PersonProcessor personProcessor = mock(PersonProcessor.class);
        when(personProcessor.processPerson(personArgumentCaptor.capture())).thenReturn(true);

        /**
         * Invoke our stubbed method
         */
        personProcessor.processPerson(Person.builder().name("hasanein").age(28).build());

        /**
         * Now we can use the ArgumentCaptor to assert on the values that our stubbed
         * method has been invoked with.
         */
        assertThat(personArgumentCaptor.getValue().getName(), is(equalTo("hasanein")));
        assertThat(personArgumentCaptor.getValue().getAge(), is(equalTo(28)));

    }

    @Test
    public void we_can_reset_the_state_of_mock_objects_after_they_have_been_used(){
        /**
         * Reseting mocks is considered to be some sort of a code smell as it is a
         * sign that we are testing too much and that our tests could be overspecified.
         * Ideally, we should be having tests that are small enough and be testing a single
         * aspect of our code at a time.
         */

        /**
         * Let's create a mock list
         */
        List list = mock(List.class);

        /**
         * Let's stub the size of the list
         */
        when(list.size()).thenReturn(10);

        /**
         * Let's test and verify the interaction
         */
        assertThat(list.size(), is(10));
        verify(list).size();
        /**
         * Let's reset our mocked list
         */
        reset(list);
        /**
         * After the reset method has been called, then all the stubbing and
         * the previous interaction data should have been erased.
         */
        verifyZeroInteractions(list);
        assertThat(list.size(), is(0));
    }

    @Test
    public void given_IHaveAMockWithOverridenDefaultReturnValues_when_IResetTheMock_then_OverridenDefaultReturnValuesShouldBePreserved(){
        ArrayList arrayList = mock(ArrayList.class, new Answer() {
            @Override
            public String answer(InvocationOnMock invocation) throws Throwable {
                return "FOO";
            }
        });

        assertThat(arrayList.get(0), is("FOO"));

        reset(arrayList);

        assertThat(arrayList.get(0), is("FOO"));

    }

    @Test(expected = UnfinishedVerificationException.class)
    public void improper_framework_usage_might_go_undetected_until_next_time_we_use_the_framework(){
        List<String> mock = mock(List.class);
        verify(mock); // Improper use that could go undetected until next time we call a Mockito function
        // if it wasn't for the explicit call of validateMockitoUsage();

        /**
         * To allow for an early detection of improper use of the framework, we need to explicitly
         * validate the usage of the framework so we don't need to wait until the next time we use
         * the framework in order to know. Also this will allow JUnit to flag the defected test method
         * rather than the next one in the case of an improper usage.
         *
         * Alternative to the invokation of the validateMockitoUsage(), we can use a MockitoRule or
         * the MockitoJUnitRunner.
         *
         * P.S. the validateMockitoUsage() can be also included in the @After method so it can run after
         * each and every test metohod.
         */
        validateMockitoUsage();
    }

    @Test
    public void use_the_fancy_BDDMockito_style_of_writing_tests() {

        Seller seller = mock(Seller.class);
        Shop shop = new Shop();

        // Given
        given(seller.askForBread()).willReturn(new Bread());

        // When
        Goods goods = shop.buyBread();

        // Then
        assertThat(goods.containsBread(), is(true));
    }

    /**
     * http://site.mockito.org/mockito/docs/current/org/mockito/Mockito.html#bdd_mockito
     */

    /**
     * TODO
     *  - What the heck argThat is all about???
     *  - And also what's best to do with OngoingStubbing
     */


    private static class PersonProcessor {
        public boolean processPerson(Person person) {
            if (person.getName().equals("hasanein")) {
                return true;
            }
            return false;
        }
    }

    @Data
    @Builder
    private static class Person {
        private String name;
        private int age;
    }

    private static class AClassWithFinalMethod {
        public final String testMethod() {
            return "Foo";
        }
    }

    private Matcher<String> isValid() {
        return new TypeSafeMatcher<String>() {
            @Override
            protected boolean matchesSafely(String someString) {
                return someString.equals("HELLO");
            }

            @Override
            public void describeTo(Description description) {
                description.appendText("Yo");
            }
        };
    }

    private static class MultipleArgumentMatchersExample {
        public String someMethodWithMultipleArguments(int x, int y, boolean isIt, String name) {
            return null;
        }

    }

    private static class Seller{
        public Bread askForBread() {
            return new Bread();
        }
    }

    private static class Bread{

    }

    private static class Shop{

        public Goods buyBread() {
            return new Goods();
        }
    }

    private static class Goods{

        public boolean containsBread() {
            return true;
        }
    }
}