package dev.cairn;

import java.io.ObjectInputStream;

public class Deserializer {
    public Object decode(ObjectInputStream stream) throws Exception {
        return stream.readObject();
    }
}
