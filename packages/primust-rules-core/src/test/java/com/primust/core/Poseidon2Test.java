package com.primust.core;

import org.junit.jupiter.api.Test;
import java.math.BigInteger;
import java.util.List;
import static org.junit.jupiter.api.Assertions.*;

class Poseidon2Test {

    @Test
    void hashSingleElement() {
        // Cross-language vector: poseidon2_hash([42]) from Python
        BigInteger result = Poseidon2.hash(List.of(BigInteger.valueOf(42)));
        BigInteger expected = new BigInteger(
            "16903261348599640072149966459073306148075553566572715541601812593675317705224"
        );
        assertEquals(expected, result);
    }

    @Test
    void hashTwoElements() {
        // Cross-language vector: poseidon2_hash([1, 2]) from Python
        BigInteger result = Poseidon2.hash(List.of(BigInteger.ONE, BigInteger.TWO));
        BigInteger expected = new BigInteger(
            "1594597865669602199208529098208508950092942746041644072252494753744672355203"
        );
        assertEquals(expected, result);
    }

    @Test
    void poseidon2BytesEmpty() {
        // Cross-language vector V1
        String result = Poseidon2.poseidon2Bytes(new byte[]{});
        assertEquals(
            "poseidon2:0b63a53787021a4a962a452c2921b3663aff1ffd8d5510540f8e659e782956f1",
            result
        );
    }

    @Test
    void poseidon2BytesHello() {
        // Cross-language vector V2
        String result = Poseidon2.poseidon2Bytes("hello".getBytes());
        assertEquals(
            "poseidon2:2c9c245e34a2bbbdc320d92f1df0e5e435de6a991a80bf9b90d908bc8b8a1960",
            result
        );
    }

    @Test
    void poseidon2BytesLongInput() {
        // Cross-language vector V4: crosses 31-byte boundary
        String result = Poseidon2.poseidon2Bytes(
            "The quick brown fox jumps over the lazy dog".getBytes()
        );
        assertEquals(
            "poseidon2:287bf2eb6b6e174667ce2927eaefe1b151b758a8db683a43e41fb4f44c074b23",
            result
        );
    }

    @Test
    void bytesToFieldElementsChunkSize() {
        // 31 bytes → 1 element
        byte[] data31 = new byte[31];
        for (int i = 0; i < 31; i++) data31[i] = (byte) i;
        assertEquals(1, Poseidon2.bytesToFieldElements(data31).size());

        // 32 bytes → 2 elements
        byte[] data32 = new byte[32];
        for (int i = 0; i < 32; i++) data32[i] = (byte) i;
        assertEquals(2, Poseidon2.bytesToFieldElements(data32).size());
    }
}
