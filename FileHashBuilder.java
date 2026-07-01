import java.io.*;
import java.nio.file.*;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.TimeZone;
import java.util.regex.Pattern;
import java.util.Set;
import java.util.HashSet;

/**
 * FileHashBuilder
 *
 * Scans the "files" folder next to this program.
 * - If a file's name is not a valid SHA-256 hex string, it is renamed to its SHA-256 hash
 *   (keeping the original extension).
 * - For every file a companion JSON is written to the "info" folder using the pattern <hash>.json.
 *
 * Supporting text files expected in the same directory as the program:
 *   public_key.txt   -> value for the "public_key" JSON field
 *   node_info.txt    -> value for the "node_info"  JSON field
 *
 * Compatible with Java 8, no external libraries.
 */
public class FileHashBuilder {

    // A valid SHA-256 filename (without extension) is exactly 64 lowercase hex chars.
    private static final Pattern SHA256_PATTERN =
            Pattern.compile("^[a-f0-9]{64}$", Pattern.CASE_INSENSITIVE);

    public static void main(String[] args) {
        // Base directory = directory that contains this program (or CWD when run from jar/class)
        File baseDir = new File(System.getProperty("user.dir"));

        File filesDir = new File(baseDir, "files");
        File infoDir  = new File(baseDir, "info");

        if (!filesDir.exists() || !filesDir.isDirectory()) {
            System.err.println("[ERROR] 'files' folder not found at: " + filesDir.getAbsolutePath());
            System.exit(1);
        }

        if (!infoDir.exists()) {
            if (infoDir.mkdirs()) {
                System.out.println("[INFO] Created 'info' folder at: " + infoDir.getAbsolutePath());
            } else {
                System.err.println("[ERROR] Could not create 'info' folder at: " + infoDir.getAbsolutePath());
                System.exit(1);
            }
        }

        // Load shared config files from the base directory
        String publicKey  = readTextFile(new File(baseDir, "public_key.txt"), "");
        String nodeInfo   = readTextFile(new File(baseDir, "node_info.txt"),  "");

        // Process every regular file inside "files/"
        File[] targets = filesDir.listFiles(File::isFile);
        if (targets == null || targets.length == 0) {
            System.out.println("[INFO] No files found in: " + filesDir.getAbsolutePath());
            return;
        }

        for (File file : targets) {
            processFile(file, infoDir, publicKey, nodeInfo);
        }

        System.out.println("[DONE] Processing complete.");

        syncFilesToIndex();

        System.out.println("[DONE] 'files.txt updated.");

    }

    private static void syncFilesToIndex() {
        Path filesDir = Paths.get("files");
        Path indexFile = Paths.get("files.txt");

        try {
            if (!Files.exists(filesDir)) {
                Files.createDirectories(filesDir);
            }

            Set<String> existing = new HashSet<>();
            if (Files.exists(indexFile)) {
                existing.addAll(Files.readAllLines(indexFile));
            } else {
                Files.createFile(indexFile);
            }

            try (DirectoryStream<Path> stream = Files.newDirectoryStream(filesDir)) {
                try (BufferedWriter writer = Files.newBufferedWriter(
                        indexFile, StandardOpenOption.APPEND)) {

                    for (Path entry : stream) {
                        if (Files.isRegularFile(entry)) {
                            String filename = entry.getFileName().toString();
                            if (!existing.contains(filename)) {
                                writer.write(filename);
                                writer.newLine();
                                existing.add(filename);
                            }
                        }
                    }
                }
            }

        } catch (IOException e) {
            System.err.println("Error syncing files to index: " + e.getMessage());
        }
    }

    // -----------------------------------------------------------------------
    // Core file processing
    // -----------------------------------------------------------------------

    private static void processFile(File file, File infoDir, String publicKey, String nodeInfo) {
        System.out.println("[INFO] Processing: " + file.getName());

        String originalName = file.getName();
        String extension    = getExtension(originalName);   // e.g. "jpg"  (no dot)
        String baseName     = getBaseName(originalName);     // e.g. "F01"

        // Compute SHA-256 of the file contents
        String hash;
        try {
            hash = sha256Hex(file);
        } catch (IOException | NoSuchAlgorithmException e) {
            System.err.println("[ERROR] Could not hash file " + originalName + ": " + e.getMessage());
            return;
        }

        // Rename the file if its base name is not already the correct SHA-256
        File finalFile = file;
        if (!isValidSha256(baseName) || !baseName.equalsIgnoreCase(hash)) {
            String newName = extension.isEmpty() ? hash : hash + "." + extension;
            finalFile = new File(file.getParentFile(), newName);

            if (finalFile.exists()) {
                System.out.println("[SKIP]  Target already exists, skipping rename: " + newName);
            } else {
                if (file.renameTo(finalFile)) {
                    System.out.println("[INFO] Renamed '" + originalName + "' -> '" + newName + "'");
                } else {
                    System.err.println("[ERROR] Could not rename '" + originalName + "' -> '" + newName + "'");
                    finalFile = file; // keep processing with the original file
                }
            }
        } else {
            System.out.println("[INFO] Filename already valid SHA-256, no rename needed.");
        }

        // Build and write the JSON info file
        long   size        = finalFile.length();
        String isoDate     = isoTimestamp(finalFile.lastModified());

        String json = buildJson(
                originalName,
                size,
                extension,
                isoDate,
                publicKey,
                hash,
                nodeInfo,
                "" // description is left empty; populate if needed
        );

        File jsonFile = new File(infoDir, hash + ".json");
        try {
            writeTextFile(jsonFile, json);
            System.out.println("[INFO] JSON written: " + jsonFile.getName());
        } catch (IOException e) {
            System.err.println("[ERROR] Could not write JSON for " + originalName + ": " + e.getMessage());
        }
    }

    // -----------------------------------------------------------------------
    // JSON builder (no external library)
    // -----------------------------------------------------------------------

    private static String buildJson(String filename, long size, String extension,
                                    String date, String publicKey,
                                    String serverPublicKey, String nodeInfo,
                                    String description) {
        StringBuilder sb = new StringBuilder();
        sb.append("{\n");
        sb.append("    \"filename\": ")        .append(jsonString(filename))       .append(",\n");
        sb.append("    \"size\": ")            .append(size)                       .append(",\n");
        sb.append("    \"extension\": ")       .append(jsonString(extension))      .append(",\n");
        sb.append("    \"date\": ")            .append(jsonString(date))           .append(",\n");
        sb.append("    \"public_key\": ")      .append(jsonString(publicKey))      .append(",\n");
        sb.append("    \"server_public_key\": ").append(jsonString(serverPublicKey)).append(",\n");
        sb.append("    \"node_info\": ")       .append(jsonString(nodeInfo))       .append(",\n");
        sb.append("    \"description\": ")     .append(jsonString(description))    .append("\n");
        sb.append("}");
        return sb.toString();
    }

    /** Wraps a value in JSON double-quotes, escaping necessary characters. */
    private static String jsonString(String value) {
        if (value == null) return "\"\"";
        StringBuilder sb = new StringBuilder("\"");
        for (char c : value.toCharArray()) {
            switch (c) {
                case '"':  sb.append("\\\""); break;
                case '\\': sb.append("\\\\"); break;
                case '\b': sb.append("\\b");  break;
                case '\f': sb.append("\\f");  break;
                case '\n': sb.append("\\n");  break;
                case '\r': sb.append("\\r");  break;
                case '\t': sb.append("\\t");  break;
                default:
                    if (c < 0x20) {
                        sb.append(String.format("\\u%04x", (int) c));
                    } else {
                        sb.append(c);
                    }
            }
        }
        sb.append("\"");
        return sb.toString();
    }

    // -----------------------------------------------------------------------
    // SHA-256 helpers
    // -----------------------------------------------------------------------

    private static String sha256Hex(File file) throws IOException, NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        try (InputStream is = new BufferedInputStream(new FileInputStream(file))) {
            byte[] buffer = new byte[8192];
            int read;
            while ((read = is.read(buffer)) != -1) {
                digest.update(buffer, 0, read);
            }
        }
        return bytesToHex(digest.digest());
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(String.format("%02x", b & 0xff));
        }
        return sb.toString();
    }

    private static boolean isValidSha256(String name) {
        return SHA256_PATTERN.matcher(name).matches();
    }

    // -----------------------------------------------------------------------
    // File / string helpers
    // -----------------------------------------------------------------------

    /** Returns the extension without the dot, or empty string if none. */
    private static String getExtension(String filename) {
        int dot = filename.lastIndexOf('.');
        return (dot >= 0 && dot < filename.length() - 1)
                ? filename.substring(dot + 1)
                : "";
    }

    /** Returns the filename without extension. */
    private static String getBaseName(String filename) {
        int dot = filename.lastIndexOf('.');
        return dot > 0 ? filename.substring(0, dot) : filename;
    }

    /** ISO-8601 timestamp with offset, e.g. 2026-06-15T06:23:59+00:00 */
    private static String isoTimestamp(long epochMillis) {
        SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ssXXX");
        sdf.setTimeZone(TimeZone.getDefault());
        return sdf.format(new Date(epochMillis));
    }

    private static String readTextFile(File file, String defaultValue) {
        if (!file.exists()) {
            System.out.println("[WARN]  File not found, using default value: " + file.getName());
            return defaultValue;
        }
        StringBuilder sb = new StringBuilder();
        try (BufferedReader br = new BufferedReader(new FileReader(file))) {
            String line;
            while ((line = br.readLine()) != null) {
                if (sb.length() > 0) sb.append("\n");
                sb.append(line);
            }
        } catch (IOException e) {
            System.err.println("[WARN]  Could not read " + file.getName() + ": " + e.getMessage());
            return defaultValue;
        }
        return sb.toString().trim();
    }

    private static void writeTextFile(File file, String content) throws IOException {
        try (BufferedWriter bw = new BufferedWriter(new FileWriter(file))) {
            bw.write(content);
        }
    }
}