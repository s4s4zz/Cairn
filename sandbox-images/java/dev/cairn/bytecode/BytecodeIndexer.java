package dev.cairn.bytecode;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.objectweb.asm.AnnotationVisitor;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.FieldVisitor;
import org.objectweb.asm.Handle;
import org.objectweb.asm.Label;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;


public final class BytecodeIndexer {
    private static final int API = Opcodes.ASM9;
    private static final long MAX_CLASS_BYTES = 32L * 1024L * 1024L;

    private BytecodeIndexer() {}

    public static void main(String[] args) throws Exception {
        if (args.length != 3) {
            System.err.println("usage: BytecodeIndexer INPUT_ROOT INPUT_MANIFEST OUTPUT_JSONL");
            System.exit(64);
        }
        Path inputRoot = Path.of(args[0]).toRealPath(LinkOption.NOFOLLOW_LINKS);
        Path manifest = Path.of(args[1]);
        Path output = Path.of(args[2]);
        try (
                BufferedReader reader = Files.newBufferedReader(manifest, StandardCharsets.UTF_8);
                BufferedWriter writer = Files.newBufferedWriter(output, StandardCharsets.UTF_8)) {
            String line;
            int lineNumber = 0;
            while ((line = reader.readLine()) != null) {
                lineNumber++;
                if (line.isEmpty()) {
                    continue;
                }
                Input input = parseInput(line, lineNumber, inputRoot);
                index(input, writer);
            }
        }
    }

    private static Input parseInput(String line, int lineNumber, Path inputRoot)
            throws IOException {
        String[] parts = line.split("\\t", -1);
        if (parts.length != 5 || !parts[0].matches("[0-9a-f]{64}")) {
            throw new IOException("invalid input manifest line " + lineNumber);
        }
        String relative = decode(parts[1]);
        if (relative.isEmpty() || relative.contains("/") || relative.contains("\\")) {
            throw new IOException("invalid staged class path on line " + lineNumber);
        }
        Path path = inputRoot.resolve(relative).normalize();
        if (!path.startsWith(inputRoot)
                || Files.isSymbolicLink(path)
                || !Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS)) {
            throw new IOException("staged class is unavailable on line " + lineNumber);
        }
        long size = Files.size(path);
        if (size <= 0 || size > MAX_CLASS_BYTES) {
            throw new IOException("staged class size is invalid on line " + lineNumber);
        }
        return new Input(
                parts[0],
                path,
                decode(parts[2]),
                emptyToNull(decode(parts[3])),
                decode(parts[4]));
    }

    private static void index(Input input, BufferedWriter writer) throws IOException {
        byte[] bytes = Files.readAllBytes(input.path());
        if (!sha256(bytes).equals(input.sha256())) {
            writeGap(writer, input, "CLASS_INPUT_INTEGRITY_FAILURE");
            return;
        }
        try {
            OffsetClassReader reader = new OffsetClassReader(bytes);
            reader.accept(new IndexClassVisitor(reader, input, writer), ClassReader.SKIP_FRAMES);
        } catch (RuntimeException error) {
            writeGap(writer, input, "CLASS_PARSE_FAILED");
        }
    }

    private static final class OffsetClassReader extends ClassReader {
        private int instructionOffset = -1;

        OffsetClassReader(byte[] bytes) {
            super(bytes);
        }

        @Override
        protected void readBytecodeInstructionOffset(int bytecodeOffset) {
            instructionOffset = bytecodeOffset;
        }

        int instructionOffset() {
            return instructionOffset;
        }
    }

    private static final class IndexClassVisitor extends ClassVisitor {
        private final OffsetClassReader reader;
        private final Input input;
        private final BufferedWriter writer;
        private final List<String> annotations = new ArrayList<>();
        private final List<Map<String, Object>> annotationDetails = new ArrayList<>();
        private String className;
        private String superName;
        private List<String> interfaces = List.of();
        private int access;
        private int version;
        private String signature;
        private String sourceFile;

        IndexClassVisitor(OffsetClassReader reader, Input input, BufferedWriter writer) {
            super(API);
            this.reader = reader;
            this.input = input;
            this.writer = writer;
        }

        @Override
        public void visit(
                int version,
                int access,
                String name,
                String signature,
                String superName,
                String[] interfaces) {
            this.version = version & 0xffff;
            this.access = access;
            this.className = dotted(name);
            this.signature = signature;
            this.superName = dotted(superName);
            this.interfaces = dotted(interfaces);
        }

        @Override
        public void visitSource(String source, String debug) {
            sourceFile = source;
        }

        @Override
        public AnnotationVisitor visitAnnotation(String descriptor, boolean visible) {
            annotations.add(descriptor);
            return new AnnotationValueVisitor(descriptor, annotationDetails);
        }

        @Override
        public FieldVisitor visitField(
                int access,
                String name,
                String descriptor,
                String signature,
                Object value) {
            Map<String, Object> record = base("field", input, className);
            record.put("name", name);
            record.put("descriptor", descriptor);
            record.put("signature", signature);
            record.put("access", access);
            writeUnchecked(writer, record);
            return null;
        }

        @Override
        public MethodVisitor visitMethod(
                int access,
                String name,
                String descriptor,
                String signature,
                String[] exceptions) {
            return new IndexMethodVisitor(
                    reader,
                    input,
                    writer,
                    className,
                    access,
                    name,
                    descriptor,
                    signature,
                    dotted(exceptions));
        }

        @Override
        public void visitEnd() {
            Map<String, Object> record = base("class", input, className);
            record.put("super_name", superName);
            record.put("interfaces", interfaces);
            record.put("access", access);
            record.put("classfile_major", version);
            record.put("signature", signature);
            record.put("source_file", sourceFile);
            record.put("annotations", sorted(annotations));
            record.put("annotation_details", annotationDetails);
            writeUnchecked(writer, record);
        }
    }

    private static final class IndexMethodVisitor extends MethodVisitor {
        private final OffsetClassReader reader;
        private final Input input;
        private final BufferedWriter writer;
        private final String className;
        private final int access;
        private final String name;
        private final String descriptor;
        private final String signature;
        private final List<String> exceptions;
        private final List<String> annotations = new ArrayList<>();
        private final List<Map<String, Object>> annotationDetails = new ArrayList<>();
        private int startLine = Integer.MAX_VALUE;
        private int endLine = -1;
        private int currentLine = -1;
        private int firstOffset = Integer.MAX_VALUE;
        private int lastOffset = -1;

        IndexMethodVisitor(
                OffsetClassReader reader,
                Input input,
                BufferedWriter writer,
                String className,
                int access,
                String name,
                String descriptor,
                String signature,
                List<String> exceptions) {
            super(API);
            this.reader = reader;
            this.input = input;
            this.writer = writer;
            this.className = className;
            this.access = access;
            this.name = name;
            this.descriptor = descriptor;
            this.signature = signature;
            this.exceptions = exceptions;
        }

        @Override
        public AnnotationVisitor visitAnnotation(String descriptor, boolean visible) {
            annotations.add(descriptor);
            return new AnnotationValueVisitor(descriptor, annotationDetails);
        }

        @Override
        public void visitLineNumber(int line, Label start) {
            currentLine = line;
            startLine = Math.min(startLine, line);
            endLine = Math.max(endLine, line);
        }

        private void instruction() {
            int offset = reader.instructionOffset();
            firstOffset = Math.min(firstOffset, offset);
            lastOffset = Math.max(lastOffset, offset);
        }

        @Override public void visitInsn(int opcode) { instruction(); }
        @Override public void visitIntInsn(int opcode, int operand) { instruction(); }
        @Override public void visitVarInsn(int opcode, int variable) { instruction(); }
        @Override public void visitTypeInsn(int opcode, String type) { instruction(); }
        @Override public void visitJumpInsn(int opcode, Label label) { instruction(); }
        @Override public void visitLdcInsn(Object value) { instruction(); }
        @Override public void visitIincInsn(int variable, int increment) { instruction(); }
        @Override public void visitTableSwitchInsn(int min, int max, Label dflt, Label... labels) { instruction(); }
        @Override public void visitLookupSwitchInsn(Label dflt, int[] keys, Label[] labels) { instruction(); }
        @Override public void visitMultiANewArrayInsn(String descriptor, int dimensions) { instruction(); }

        @Override
        public void visitFieldInsn(int opcode, String owner, String name, String descriptor) {
            instruction();
            Map<String, Object> record = methodBase("field-access");
            record.put("bytecode_offset", reader.instructionOffset());
            record.put("source_line", nullableLine());
            record.put("opcode", opcode);
            record.put("target_owner", dotted(owner));
            record.put("target_name", name);
            record.put("target_descriptor", descriptor);
            writeUnchecked(writer, record);
        }

        @Override
        public void visitMethodInsn(
                int opcode,
                String owner,
                String name,
                String descriptor,
                boolean isInterface) {
            instruction();
            Map<String, Object> record = methodBase("call");
            record.put("bytecode_offset", reader.instructionOffset());
            record.put("source_line", nullableLine());
            record.put("opcode", opcode);
            record.put("edge_kind", edgeKind(opcode));
            record.put("target_owner", dotted(owner));
            record.put("target_name", name);
            record.put("target_descriptor", descriptor);
            record.put("interface", isInterface);
            writeUnchecked(writer, record);
        }

        @Override
        public void visitInvokeDynamicInsn(
                String name,
                String descriptor,
                Handle bootstrapMethodHandle,
                Object... bootstrapMethodArguments) {
            instruction();
            Map<String, Object> record = methodBase("call");
            record.put("bytecode_offset", reader.instructionOffset());
            record.put("source_line", nullableLine());
            record.put("opcode", Opcodes.INVOKEDYNAMIC);
            record.put("edge_kind", "inferred");
            record.put("target_owner", null);
            record.put("target_name", null);
            record.put("target_descriptor", null);
            record.put("interface", bootstrapMethodHandle.isInterface());
            record.put("callsite_name", name);
            record.put("callsite_descriptor", descriptor);
            record.put("bootstrap_owner", dotted(bootstrapMethodHandle.getOwner()));
            record.put("bootstrap_name", bootstrapMethodHandle.getName());
            record.put("bootstrap_descriptor", bootstrapMethodHandle.getDesc());
            writeUnchecked(writer, record);
        }

        @Override
        public void visitEnd() {
            Map<String, Object> record = methodBase("method");
            record.put("access", access);
            record.put("signature", signature);
            record.put("exceptions", exceptions);
            record.put("annotations", sorted(annotations));
            record.put("annotation_details", annotationDetails);
            record.put("start_line", startLine == Integer.MAX_VALUE ? null : startLine);
            record.put("end_line", endLine < 0 ? null : endLine);
            record.put("first_bytecode_offset", firstOffset == Integer.MAX_VALUE ? null : firstOffset);
            record.put("last_bytecode_offset", lastOffset < 0 ? null : lastOffset);
            writeUnchecked(writer, record);
        }

        private Map<String, Object> methodBase(String kind) {
            Map<String, Object> record = base(kind, input, className);
            record.put("method_name", name);
            record.put("method_descriptor", descriptor);
            return record;
        }

        private Integer nullableLine() {
            return currentLine < 0 ? null : currentLine;
        }
    }

    private static final class AnnotationValueVisitor extends AnnotationVisitor {
        private final String descriptor;
        private final List<Map<String, Object>> sink;
        private final Map<String, Object> members = new LinkedHashMap<>();

        AnnotationValueVisitor(String descriptor, List<Map<String, Object>> sink) {
            super(API);
            this.descriptor = descriptor;
            this.sink = sink;
        }

        @Override
        public void visit(String name, Object value) {
            if (name != null) {
                members.put(name, stringify(value));
            }
        }

        @Override
        public void visitEnum(String name, String enumDescriptor, String value) {
            if (name != null) {
                members.put(name, value);
            }
        }

        @Override
        public AnnotationVisitor visitArray(String name) {
            List<String> values = new ArrayList<>();
            return new AnnotationVisitor(API) {
                @Override
                public void visit(String member, Object value) {
                    values.add(stringify(value));
                }

                @Override
                public void visitEnum(String member, String enumDescriptor, String value) {
                    values.add(value);
                }

                @Override
                public void visitEnd() {
                    if (name != null) {
                        members.put(name, values);
                    }
                }
            };
        }

        @Override
        public AnnotationVisitor visitAnnotation(String name, String nestedDescriptor) {
            // Nested annotations are not needed by the authorization topology.
            return null;
        }

        @Override
        public void visitEnd() {
            Map<String, Object> detail = new LinkedHashMap<>();
            detail.put("descriptor", descriptor);
            detail.put("members", members);
            sink.add(detail);
        }
    }

    private static String stringify(Object value) {
        if (value instanceof Type type) {
            return type.getClassName();
        }
        return String.valueOf(value);
    }

    private static String edgeKind(int opcode) {
        return switch (opcode) {
            case Opcodes.INVOKESTATIC, Opcodes.INVOKESPECIAL -> "exact";
            case Opcodes.INVOKEVIRTUAL, Opcodes.INVOKEINTERFACE -> "inferred";
            default -> "inferred";
        };
    }

    private static Map<String, Object> base(String kind, Input input, String className) {
        Map<String, Object> record = new LinkedHashMap<>();
        record.put("record_kind", kind);
        record.put("logical_path", input.logicalPath());
        record.put("container_path", input.containerPath());
        record.put("entry_path", input.entryPath());
        record.put("class_sha256", input.sha256());
        record.put("class_name", className);
        return record;
    }

    private static void writeGap(BufferedWriter writer, Input input, String reasonCode)
            throws IOException {
        Map<String, Object> record = base("coverage-gap", input, null);
        record.put("reason_code", reasonCode);
        write(writer, record);
    }

    private static void writeUnchecked(BufferedWriter writer, Map<String, Object> record) {
        try {
            write(writer, record);
        } catch (IOException error) {
            throw new OutputFailure(error);
        }
    }

    private static void write(BufferedWriter writer, Map<String, Object> record)
            throws IOException {
        writer.write(json(record));
        writer.newLine();
    }

    private static String json(Object value) {
        if (value == null) {
            return "null";
        }
        if (value instanceof String text) {
            return quote(text);
        }
        if (value instanceof Number || value instanceof Boolean) {
            return value.toString();
        }
        if (value instanceof List<?> values) {
            StringBuilder output = new StringBuilder("[");
            for (int index = 0; index < values.size(); index++) {
                if (index > 0) output.append(',');
                output.append(json(values.get(index)));
            }
            return output.append(']').toString();
        }
        if (value instanceof Map<?, ?> values) {
            StringBuilder output = new StringBuilder("{");
            boolean first = true;
            for (Map.Entry<?, ?> entry : values.entrySet()) {
                if (!first) output.append(',');
                first = false;
                output.append(quote((String) entry.getKey()));
                output.append(':').append(json(entry.getValue()));
            }
            return output.append('}').toString();
        }
        throw new IllegalArgumentException("unsupported JSON value");
    }

    private static String quote(String value) {
        StringBuilder output = new StringBuilder(value.length() + 2).append('"');
        for (int index = 0; index < value.length(); index++) {
            char character = value.charAt(index);
            switch (character) {
                case '"' -> output.append("\\\"");
                case '\\' -> output.append("\\\\");
                case '\b' -> output.append("\\b");
                case '\f' -> output.append("\\f");
                case '\n' -> output.append("\\n");
                case '\r' -> output.append("\\r");
                case '\t' -> output.append("\\t");
                default -> {
                    if (character < 0x20 || Character.isSurrogate(character)) {
                        output.append(String.format("\\u%04x", (int) character));
                    } else {
                        output.append(character);
                    }
                }
            }
        }
        return output.append('"').toString();
    }

    private static String decode(String value) throws IOException {
        try {
            return new String(Base64.getUrlDecoder().decode(value), StandardCharsets.UTF_8);
        } catch (IllegalArgumentException error) {
            throw new IOException("invalid base64url input manifest value", error);
        }
    }

    private static String emptyToNull(String value) {
        return value.isEmpty() ? null : value;
    }

    private static String dotted(String value) {
        return value == null ? null : value.replace('/', '.');
    }

    private static List<String> dotted(String[] values) {
        if (values == null || values.length == 0) {
            return List.of();
        }
        List<String> output = new ArrayList<>(values.length);
        for (String value : values) output.add(dotted(value));
        return output;
    }

    private static List<String> sorted(List<String> values) {
        return values.stream().distinct().sorted().toList();
    }

    private static String sha256(byte[] bytes) {
        try {
            return java.util.HexFormat.of().formatHex(
                    MessageDigest.getInstance("SHA-256").digest(bytes));
        } catch (NoSuchAlgorithmException error) {
            throw new IllegalStateException(error);
        }
    }

    private record Input(
            String sha256,
            Path path,
            String logicalPath,
            String containerPath,
            String entryPath) {}

    private static final class OutputFailure extends RuntimeException {
        OutputFailure(IOException cause) {
            super(cause);
        }
    }
}
