package uk.gov.dwp.maze;

import org.junit.Before;
import org.junit.Test;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.Matchers.notNullValue;
import static org.junit.Assert.assertThat;


public class MazeTest {
    private Maze maze;

    @Before
    public void setup() {
        maze = new Maze();
    }

    @Test
    public void should_create_system_under_test() {
        assertThat(maze, is(notNullValue()));
    }
}