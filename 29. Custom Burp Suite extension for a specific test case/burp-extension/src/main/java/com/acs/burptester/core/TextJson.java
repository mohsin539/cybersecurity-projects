package com.acs.burptester.core;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public final class TextJson {

    private TextJson() {
    }

    public static Map<String, Object> parseObject(String json) {
        Tokenizer t = new Tokenizer(json);
        Object value = t.readValue();
        if (!(value instanceof Map<?, ?>)) {
            throw new IllegalArgumentException("expected a JSON object");
        }
        return castMap(value);
    }

    public static List<Object> parseArray(String json) {
        Tokenizer t = new Tokenizer(json);
        Object value = t.readValue();
        if (!(value instanceof List<?>)) {
            throw new IllegalArgumentException("expected a JSON array");
        }
        @SuppressWarnings("unchecked")
        List<Object> list = (List<Object>) value;
        return list;
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> castMap(Object value) {
        return (Map<String, Object>) value;
    }

    public static String stringify(Object value) {
        StringBuilder sb = new StringBuilder();
        write(sb, value);
        return sb.toString();
    }

    private static void write(StringBuilder sb, Object value) {
        if (value == null) {
            sb.append("null");
        } else if (value instanceof String s) {
            writeString(sb, s);
        } else if (value instanceof Boolean || value instanceof Number) {
            sb.append(value);
        } else if (value instanceof Map<?, ?> map) {
            sb.append('{');
            boolean first = true;
            for (Map.Entry<?, ?> e : map.entrySet()) {
                if (!first) {
                    sb.append(',');
                }
                first = false;
                writeString(sb, String.valueOf(e.getKey()));
                sb.append(':');
                write(sb, e.getValue());
            }
            sb.append('}');
        } else if (value instanceof List<?> list) {
            sb.append('[');
            boolean first = true;
            for (Object item : list) {
                if (!first) {
                    sb.append(',');
                }
                first = false;
                write(sb, item);
            }
            sb.append(']');
        } else {
            writeString(sb, String.valueOf(value));
        }
    }

    private static void writeString(StringBuilder sb, String s) {
        sb.append('"');
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"' -> sb.append("\\\"");
                case '\\' -> sb.append("\\\\");
                case '\n' -> sb.append("\\n");
                case '\r' -> sb.append("\\r");
                case '\t' -> sb.append("\\t");
                case '\b' -> sb.append("\\b");
                case '\f' -> sb.append("\\f");
                default -> {
                    if (c < 0x20) {
                        sb.append(String.format("\\u%04x", (int) c));
                    } else {
                        sb.append(c);
                    }
                }
            }
        }
        sb.append('"');
    }

    private static final class Tokenizer {
        private final String src;
        private int pos;

        Tokenizer(String src) {
            this.src = src;
        }

        Object readValue() {
            skipWs();
            if (pos >= src.length()) {
                throw new IllegalArgumentException("unexpected end of JSON");
            }
            char c = src.charAt(pos);
            return switch (c) {
                case '{' -> readObject();
                case '[' -> readArray();
                case '"' -> readString(true);
                case 't' -> { consumeKeyword("true"); yield Boolean.TRUE; }
                case 'f' -> { consumeKeyword("false"); yield Boolean.FALSE; }
                case 'n' -> { consumeKeyword("null"); yield null; }
                default -> readNumber();
            };
        }

        private Map<String, Object> readObject() {
            Map<String, Object> map = new LinkedHashMap<>();
            pos++;
            skipWs();
            if (peek() == '}') {
                pos++;
                return map;
            }
            while (true) {
                skipWs();
                String key = readString(true);
                skipWs();
                expect(':');
                pos++;
                Object value = readValue();
                map.put(key, value);
                skipWs();
                char c = peek();
                if (c == ',') {
                    pos++;
                } else if (c == '}') {
                    pos++;
                    return map;
                } else {
                    throw new IllegalArgumentException("expected ',' or '}' at " + pos);
                }
            }
        }

        private List<Object> readArray() {
            List<Object> list = new ArrayList<>();
            pos++;
            skipWs();
            if (peek() == ']') {
                pos++;
                return list;
            }
            while (true) {
                list.add(readValue());
                skipWs();
                char c = peek();
                if (c == ',') {
                    pos++;
                } else if (c == ']') {
                    pos++;
                    return list;
                } else {
                    throw new IllegalArgumentException("expected ',' or ']' at " + pos);
                }
            }
        }

        private String readString(boolean jsonString) {
            skipWs();
            expect('"');
            pos++;
            StringBuilder sb = new StringBuilder();
            while (pos < src.length()) {
                char c = src.charAt(pos++);
                if (c == '"') {
                    return sb.toString();
                }
                if (c == '\\') {
                    char esc = src.charAt(pos++);
                    switch (esc) {
                        case '"' -> sb.append('"');
                        case '\\' -> sb.append('\\');
                        case '/' -> sb.append('/');
                        case 'b' -> sb.append('\b');
                        case 'f' -> sb.append('\f');
                        case 'n' -> sb.append('\n');
                        case 'r' -> sb.append('\r');
                        case 't' -> sb.append('\t');
                        case 'u' -> sb.append((char) Integer.parseInt(src.substring(pos, pos + 4), 16));
                        default -> throw new IllegalArgumentException("bad escape \\" + esc);
                    }
                    if (esc == 'u') {
                        pos += 4;
                    }
                } else {
                    sb.append(c);
                }
            }
            throw new IllegalArgumentException("unterminated string");
        }

        private Object readNumber() {
            int start = pos;
            while (pos < src.length() && (Character.isDigit(src.charAt(pos)) || src.charAt(pos) == '-'
                    || src.charAt(pos) == '+' || src.charAt(pos) == '.' || src.charAt(pos) == 'e'
                    || src.charAt(pos) == 'E')) {
                pos++;
            }
            String token = src.substring(start, pos);
            try {
                if (token.contains(".") || token.contains("e") || token.contains("E")) {
                    return Double.parseDouble(token);
                }
                return Long.parseLong(token);
            } catch (NumberFormatException e) {
                throw new IllegalArgumentException("invalid number: " + token);
            }
        }

        private void consumeKeyword(String kw) {
            if (!src.startsWith(kw, pos)) {
                throw new IllegalArgumentException("expected " + kw + " at " + pos);
            }
            pos += kw.length();
        }

        private void skipWs() {
            while (pos < src.length() && Character.isWhitespace(src.charAt(pos))) {
                pos++;
            }
        }

        private char peek() {
            if (pos >= src.length()) {
                return 0;
            }
            return src.charAt(pos);
        }

        private void expect(char c) {
            if (peek() != c) {
                throw new IllegalArgumentException("expected '" + c + "' at " + pos);
            }
        }
    }
}