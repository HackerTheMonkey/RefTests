package concurrency;

import org.junit.Before;
import org.junit.Test;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.notNullValue;


public class EnergySourceTest {
    private EnergySource energySource;

    @Before
    public void setup() {
        energySource = new EnergySource();
    }

    @Test
    public void should_create_system_under_test() {
        assertThat(energySource, is(notNullValue()));
    }

    @Test
    public void unused_energy_source_(){

    }
}