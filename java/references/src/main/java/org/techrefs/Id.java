package org.techrefs;

public class Id<T> {
    private final Class<T> className;
    private final long someValue;

    public Id(Class<T> className, long someValue) {
        this.className = className;
        this.someValue = someValue;
    }
}
