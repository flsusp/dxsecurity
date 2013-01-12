package br.com.dextra.security.utils;

import com.google.common.base.Joiner;

public class StringConcatUtil {

    public static String concat(Object... values) {
        return Joiner.on("").join(values);
    }
}
