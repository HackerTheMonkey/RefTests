package org.techrefs;

import org.hamcrest.Description;
import org.hamcrest.Matcher;
import org.hamcrest.MatcherAssert;
import org.hamcrest.TypeSafeMatcher;
import org.junit.Test;
import org.mockito.InOrder;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import static org.hamcrest.CoreMatchers.*;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.mockito.Mockito.*;

public class MockitoReferenceTest {

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

    @Test(expected = RuntimeException.class)
    public void lets_do_some_basic_stubbing(){
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
    public void last_stubbing_always_win(){
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

        assertThat((String)map.get("Foo"), is(not(equalTo("Bar"))));

        /**
         * even when mixing argument matchers and literal Strings
         */
        Map yetAnotherMap = mock(Map.class);

        when(yetAnotherMap.get(anyString())).thenReturn("Bar");
        when(yetAnotherMap.get(anyString())).thenReturn("I don't know it!");

        assertThat((String) yetAnotherMap.get("Foo"), is(not(equalTo("Bar"))));
    }


    @Test
    public void stubbing_using_mockito_builtin_agrument_matchers_sameAppliesOnVerification(){
        /**
         * The built-in argument matchers are in the form of anyX()
         */
        List list = mock(List.class);

        when(list.contains(anyInt())).thenReturn(true);

        assertThat(list.contains(111), is(true));
    }

    @Test
    public void stubbing_using_natural_equals_java_style_thePreferredWay_sameAppliesOnVerification(){
        List list = mock(List.class);

        when(list.contains("something")).thenReturn(true);

        assertThat(list.contains("something"), is(true));
    }

    @Test
    public void stubbing_using_custom_hamcrest_matchers_sameAppliesOnVerification(){
        List list = mock(List.class);

        when(list.contains(argThat(isValid()))).thenReturn(true);

        assertThat(list.contains(111), is(false));
        assertThat(list.contains("HELLO"), is(true));
    }

    @Test
    public void when_using_argument_matchers_then_all_arguments_have_to_be_matchers_weather_stubbing_or_mocking(){
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
    public void stubbing_void_methods(){
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
    public void in_order_verification_for_calls_on_a_single_mock_object(){
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
    public void lets_do_inOrder_verification_on_multiple_mocks(){
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
    public void we_can_also_make_sure_that_calls_never_happened_on_mocks(){
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
    public void there_is_a_way_to_find_out_if_there_is_any_redundant_mock_invocations_that_we_didnt_know_we_were_making(){
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
    public void we_can_stub_multiple_method_calls_as_well(){
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
    public void dynammic_stubbing_this_is_an_advanced_but_less_recommended_way_of_stubbing_with_call_backs(){
        List<String> mockList = mock(ArrayList.class);

        when(mockList.get(1)).thenReturn("Foo");

        when(mockList.get(0)).then(new Answer<String>() {
            @Override
            public String answer(InvocationOnMock invocationOnMock) throws Throwable {
                /**
                 * We can have access to the arguments that the stubbed method has
                 * been called with.
                 */
                System.out.println("Arguments: " + Arrays.asList(invocationOnMock.getArguments()));;

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
                System.out.println("Calling another stubbed method: " + ((List<String>)invocationOnMock.getMock()).get(1));

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
        doReturn("Bar").when(spy).testMethod();

        assertThat(spy.testMethod(), is(equalTo("Foo")));

        /**
         * We can't even verify final methods on a spy, big time.
         */
//        verify(spy, times(1)).testMethod();
    }

    private static class AClassWithFinalMethod{
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

    private static class MultipleArgumentMatchersExample{
        public String someMethodWithMultipleArguments(int x, int y, boolean isIt, String name){
            return null;
        }

    }
}
