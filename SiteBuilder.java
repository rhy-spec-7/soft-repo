import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.regex.Pattern;
import java.util.Set;
import java.util.HashSet;

/**
 * SiteBuilder — Java 8, no external libraries.
 *
 * Single-pass pipeline over the "files/" directory:
 *   1. For each file, check whether the stem is a valid SHA-256 hex string.
 *      - Already hashed (stem == 64 hex chars): read info/<hash>.json and
 *        derive categories from the JSON "filename" field.
 *      - Not yet hashed: hash the file, rename it to <hash>[.ext], write
 *        info/<hash>.json, and derive categories from the original filename.
 *   2. Generate the full static site (root pages + category pages).
 *
 * Directory layout (input):
 *   files/         — media files (named <sha256>[.ext] or original names)
 *   info/          — JSON metadata per file  (<sha256>.json)
 *   thumbs/        — optional video thumbnails  (<sha256>.jpg)
 *   public_key.txt — written to every new JSON as "public_key"
 *   node_info.txt  — written to every new JSON as "node_info"
 *
 * Generated output:
 *   index.html                      — root page 1
 *   pages/index_<N>.html            — root pages 2+
 *   categories/<tag>/index.html     — category page 1
 *   categories/<tag>/index_<N>.html — category pages 2+
 *
 * Usage:
 *   javac SiteBuilder.java
 *   java  SiteBuilder [baseDir]
 */
public class SiteBuilder {

    // -- Configuration ---------------------------------------------------------
    static final int  PER_PAGE    = 18;
    static final long MAX_PAGE_KB = 100 * 1024L;
    static final int  MAX_TAGS    = 10;
    static final int  SIDEBAR_MAX = 100;
    static final int  PAG_BLOCK   = 100;

    static final Pattern SHA256_PATTERN =
            Pattern.compile("^[a-f0-9]{64}$", Pattern.CASE_INSENSITIVE);

    static final Set<String> IMAGE_EXTS = new HashSet<>(Arrays.asList(
            "jpg","jpeg","png","gif","webp","avif","bmp","tiff","tif"));
    static final Set<String> VIDEO_EXTS = new HashSet<>(Arrays.asList(
            "mp4","mkv","avi","mov","wmv","flv","webm","m4v","mpg","mpeg","3gp","ts","m2ts"));

    // -- Entry point -----------------------------------------------------------

    public static void main(String[] args) throws Exception {
        String baseDirStr = args.length > 0 ? args[0] : System.getProperty("user.dir");
        Path   baseDir    = Paths.get(baseDirStr).toAbsolutePath().normalize();

        System.out.println("\n  SiteBuilder (Java 8)");
        System.out.println("-".repeat(44));
        System.out.println("Base dir: " + baseDir);

        Path filesDir  = baseDir.resolve("files");
        Path infoDir   = baseDir.resolve("info");
        Path thumbsDir = baseDir.resolve("thumbs");
        Path catsDir   = baseDir.resolve("categories");
        Path pagesDir  = baseDir.resolve("pages");

        // Create skeleton if files/ is missing
        if (!Files.isDirectory(filesDir)) {
            System.out.println("?  'files/' not found. Creating skeleton…");
            Files.createDirectories(filesDir);
            Files.createDirectories(infoDir);
            Files.createDirectories(thumbsDir);
            Files.write(filesDir.resolve("README.txt"),
                    "Place media files here.".getBytes(StandardCharsets.UTF_8));
            System.out.println("   Skeleton created. Add files and run again.");
            return;
        }

        Files.createDirectories(infoDir);
        Files.createDirectories(catsDir);
        Files.createDirectories(pagesDir);

        // Load shared config
        String publicKey = readTextFile(baseDir.resolve("public_key.txt"), "");
        String nodeInfo  = readTextFile(baseDir.resolve("node_info.txt"),  "");

        // -- Single scan of files/ ---------------------------------------------
        List<Path> fileList = new ArrayList<>();
        try (DirectoryStream<Path> ds = Files.newDirectoryStream(filesDir)) {
            for (Path p : ds) { if (Files.isRegularFile(p)) fileList.add(p); }
        }
        Collections.sort(fileList);

        if (fileList.isEmpty()) {
            System.out.println("?  No files in 'files/'. Aborting.");
            return;
        }

        // tagMap built during the single pass
        Map<String, List<FileEntry>> tagMap = new LinkedHashMap<>();

        System.out.println("\n-- Phase 1: hashing / JSON reading ------------------");

        for (int idx = 0; idx < fileList.size(); idx++) {
            Path   filePath  = fileList.get(idx);
            String fileName  = filePath.getFileName().toString();
            String baseName  = getBaseName(fileName);
            String extension = getExtension(fileName);
            String fileExt   = extension.toLowerCase();

            String originalFilename; // display name used for category derivation
            String hash;
            Path   finalPath = filePath;
            Map<String, String> meta;
            String json;

            if (isValidSha256(baseName)) {
                // ---------------------------------------------------------------
                // BRANCH A: filename stem is already a valid SHA-256 hash.
                // Do NOT re-hash. Read display name from info/<hash>.json.
                // ---------------------------------------------------------------
                hash = baseName;
                System.out.println("[INFO]  Already hashed: " + fileName);

                Path jsonFile = infoDir.resolve(hash + ".json");
                if (!Files.exists(jsonFile)) {
                    System.err.println("[WARN]  No JSON found for " + fileName
                            + " (expected " + jsonFile + "). Skipping.");
                    continue;
                }
                try {
                    json = new String(Files.readAllBytes(jsonFile), StandardCharsets.UTF_8);
                } catch (IOException e) {
                    System.err.println("[ERROR] Could not read " + jsonFile.getFileName()
                            + ": " + e.getMessage());
                    continue;
                }
                meta = parseSimpleJson(json);

                // Display name comes from JSON "filename" field
                String jsonFilename = meta.getOrDefault("filename", "").trim();
                originalFilename = jsonFilename.isEmpty()
                        ? hash
                        : jsonFilename.replace("_", " ").trim();

            } else {
                // ---------------------------------------------------------------
                // BRANCH B: filename is NOT a valid SHA-256 hash.
                // Hash the file, rename it, write JSON, derive categories from
                // the original filename (before hashing).
                // ---------------------------------------------------------------
                try {
                    hash = sha256Hex(filePath.toFile());
                } catch (IOException | NoSuchAlgorithmException e) {
                    System.err.println("[ERROR] Could not hash " + fileName + ": " + e.getMessage());
                    continue;
                }

                // Rename to <hash>[.ext]
                String newName = extension.isEmpty() ? hash : hash + "." + extension;
                Path   target  = filePath.getParent().resolve(newName);
                if (Files.exists(target)) {
                    System.out.println("[SKIP]  Already exists, skipping rename: " + newName);
                } else {
                    try {
                        Files.move(filePath, target);
                        System.out.println("[INFO]  Renamed '" + fileName + "' -> '" + newName + "'");
                        finalPath = target;
                        fileList.set(idx, target);
                    } catch (IOException e) {
                        System.err.println("[ERROR] Could not rename '" + fileName + "': " + e.getMessage());
                    }
                }

                // Write companion JSON (uses the original filename)
                long   size    = Files.size(finalPath);
                String isoDate = isoTimestamp(Files.getLastModifiedTime(finalPath).toMillis());
                json = buildJson(fileName, size, extension, isoDate,
                                 publicKey, hash, nodeInfo, "");
                Path jsonFile = infoDir.resolve(hash + ".json");
                writeFile(jsonFile, json);
                System.out.println("[INFO]  JSON written: " + jsonFile.getFileName());

                meta = parseSimpleJson(json);

                // Display name comes from the original filename (before hashing)
                originalFilename = baseName.replace("_", " ").trim();
            }

            // -- Build FileEntry (common to both branches) --------------------
            String finalFileName = finalPath.getFileName().toString();
            String finalStem     = getBaseName(finalFileName);

            boolean isVideo = VIDEO_EXTS.contains(fileExt);
            String  thumb   = null;
            if (isVideo) {
                Path tf = thumbsDir.resolve(finalStem + ".jpg");
                if (Files.exists(tf)) thumb = "thumbs/" + finalStem + ".jpg";
            }

            List<String> tags = splitIntoTags(originalFilename);
            if (!fileExt.isEmpty() && !tags.contains(fileExt)) tags.add(fileExt);

            FileEntry entry = new FileEntry(finalFileName, finalStem, fileExt,
                                            meta, originalFilename, isVideo, thumb);
            for (String tag : tags) {
                tagMap.computeIfAbsent(tag, k -> new ArrayList<>()).add(entry);
            }
        }

        System.out.println("\n-- Phase 2: generating static site ------------------");
        System.out.println("Found " + tagMap.size() + " categories from "
                + countUniqueFiles(tagMap) + " files.");

        // Build sidebar (sorted by count DESC, then alpha)
        List<CategoryInfo> allCats = new ArrayList<>();
        for (Map.Entry<String, List<FileEntry>> e : tagMap.entrySet())
            allCats.add(new CategoryInfo(e.getKey(), e.getValue().size()));
        Collections.sort(allCats, new Comparator<CategoryInfo>() {
            public int compare(CategoryInfo a, CategoryInfo b) {
                int cmp = Integer.compare(b.count, a.count);
                return cmp != 0 ? cmp : a.name.compareTo(b.name);
            }
        });
        List<CategoryInfo> sidebarCats = allCats.size() > SIDEBAR_MAX
                ? allCats.subList(0, SIDEBAR_MAX) : allCats;

        // Generate category pages
        for (Map.Entry<String, List<FileEntry>> e : tagMap.entrySet())
            generateCategoryPages(catsDir, e.getKey(), e.getValue(), sidebarCats);

        // Generate root pages (deduplicated, in scan order)
        List<FileEntry> rootEntries = collectUniqueEntries(tagMap, fileList);
        System.out.println("\nGenerating root index…");
        generateRootPages(baseDir, pagesDir, rootEntries, sidebarCats);

        System.out.println("\n Done!\n");
        syncFilesToIndex();
        System.out.println("\n 'files.txt' updated.\n");


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


    // -- SHA-256 validation ----------------------------------------------------

    static boolean isValidSha256(String name) {
        return SHA256_PATTERN.matcher(name).matches();
    }

    // -- SHA-256 hashing -------------------------------------------------------

    static String sha256Hex(File file) throws IOException, NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        try (InputStream is = new BufferedInputStream(new FileInputStream(file))) {
            byte[] buf = new byte[8192];
            int n;
            while ((n = is.read(buf)) != -1) digest.update(buf, 0, n);
        }
        return bytesToHex(digest.digest());
    }

    static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) sb.append(String.format("%02x", b & 0xff));
        return sb.toString();
    }

    // -- JSON building ---------------------------------------------------------

    static String buildJson(String filename, long size, String extension,
                            String date, String publicKey,
                            String serverPublicKey, String nodeInfo,
                            String description) {
        StringBuilder sb = new StringBuilder();
        sb.append("{\n");
        sb.append("    \"filename\": ")         .append(jsonString(filename))        .append(",\n");
        sb.append("    \"size\": ")             .append(size)                        .append(",\n");
        sb.append("    \"extension\": ")        .append(jsonString(extension))       .append(",\n");
        sb.append("    \"date\": ")             .append(jsonString(date))            .append(",\n");
        sb.append("    \"public_key\": ")       .append(jsonString(publicKey))       .append(",\n");
        sb.append("    \"server_public_key\": ").append(jsonString(serverPublicKey)) .append(",\n");
        sb.append("    \"node_info\": ")        .append(jsonString(nodeInfo))        .append(",\n");
        sb.append("    \"description\": ")      .append(jsonString(description))     .append("\n");
        sb.append("}");
        return sb.toString();
    }

    static String jsonString(String value) {
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
                    if (c < 0x20) sb.append(String.format("\\u%04x", (int) c));
                    else          sb.append(c);
            }
        }
        sb.append("\"");
        return sb.toString();
    }

    // -- File I/O helpers ------------------------------------------------------

    static String readTextFile(Path path, String defaultValue) {
        if (!Files.exists(path)) {
            System.out.println("[WARN]  Not found, using default: " + path.getFileName());
            return defaultValue;
        }
        try {
            return new String(Files.readAllBytes(path), StandardCharsets.UTF_8).trim();
        } catch (IOException e) {
            System.err.println("[WARN]  Could not read " + path.getFileName() + ": " + e.getMessage());
            return defaultValue;
        }
    }

    // -- Category page generation ----------------------------------------------

    static void generateCategoryPages(Path catsDir, String catName,
            List<FileEntry> entries, List<CategoryInfo> sidebarCats) throws IOException {

        Path catDir = catsDir.resolve(catName);
        Files.createDirectories(catDir);

        // Remove stale extra pages
        try (DirectoryStream<Path> ds = Files.newDirectoryStream(catDir, "index_*.html"))
            { for (Path p : ds) Files.delete(p); }

        String displayName = toDisplayName(catName);
        int    total       = entries.size();
        List<List<FileEntry>> pages = splitIntoPages(entries);
        int totalPages = pages.size();

        for (int pi = 0; pi < totalPages; pi++) {
            int             page  = pi + 1;
            List<FileEntry> slice = pages.get(pi);
            int start = countBefore(pages, pi) + 1;
            int end   = start + slice.size() - 1;

            StringBuilder tiles = new StringBuilder();
            for (int i = 0; i < slice.size(); i++) {
                FileEntry f     = slice.get(i);
                int       delay = i * 50;
                String fileHref     = "../../files/" + htmlEsc(f.fileName);
                String thumbDisplay = f.thumbSrc != null ? "../../" + f.thumbSrc : null;
                String imgSrc;
                if      (f.isVideo && thumbDisplay != null) imgSrc = thumbDisplay;
                else if (IMAGE_EXTS.contains(f.ext))        imgSrc = fileHref;
                else                                         imgSrc = placeholderSvg();

                String extBadge  = f.ext.isEmpty() ? "FILE" : f.ext.toUpperCase();
                String nameBadge = truncateName(f.originalFilename, 18) + "."
                                   + (f.ext.isEmpty() ? "file" : f.ext);
                tiles.append(tile(fileHref, htmlEsc(f.originalFilename), imgSrc,
                        extBadge, nameBadge, buildMetaHtml(f), delay));
            }

            String pLabel = totalPages > 1 ? " – Page " + page + " of " + totalPages : "";
            String cLabel = total == 1 ? "1 file" : total + " files";
            String rLabel = totalPages > 1
                    ? "Showing " + start + "–" + end + " of " + total + " files" : cLabel;

            String sidebar = buildSidebar(sidebarCats, catName, "../../", false);
            String pagNav  = renderPagination(page, totalPages, start - 1, false, 0);
            String backLink = "../../index.html";

            String html = pageShell(
                    htmlEsc(displayName) + pLabel + " – SiteBuilder",
                    buildCategoryBody(displayName, pLabel, rLabel, cLabel,
                            tiles.toString(), pagNav, backLink, sidebar));

            String fname = page == 1 ? "index.html" : "index_" + page + ".html";
            writeFile(catDir.resolve(fname), html);
        }
        System.out.println("  ? categories/" + catName + "/ ? " + total
                + " items, " + totalPages + " page(s)");
    }

    // -- Root page generation --------------------------------------------------

    static void generateRootPages(Path baseDir, Path pagesDir,
            List<FileEntry> rootEntries, List<CategoryInfo> sidebarCats) throws IOException {

        // Clean stale pages
        try (DirectoryStream<Path> ds = Files.newDirectoryStream(baseDir, "index_*.html"))
            { for (Path p : ds) Files.delete(p); }
        try (DirectoryStream<Path> ds = Files.newDirectoryStream(pagesDir, "index_*.html"))
            { for (Path p : ds) Files.delete(p); }

        int total      = rootEntries.size();
        List<List<FileEntry>> pages = splitIntoPages(rootEntries);
        int totalPages = pages.size();

        for (int pi = 0; pi < totalPages; pi++) {
            int             page     = pi + 1;
            List<FileEntry> slice    = pages.get(pi);
            int             startIdx = countBefore(pages, pi);
            int             startNum = startIdx + 1;
            int             endNum   = startNum + slice.size() - 1;

            boolean inPages = page > 1;

            StringBuilder tiles = new StringBuilder();
            for (int i = 0; i < slice.size(); i++) {
                FileEntry f     = slice.get(i);
                int       delay = i * 60;
                String fileHref     = (inPages ? "../" : "") + "files/" + htmlEsc(f.fileName);
                String thumbDisplay = f.thumbSrc != null
                        ? (inPages ? "../" : "") + f.thumbSrc : null;
                String imgSrc;
                if      (f.isVideo && thumbDisplay != null) imgSrc = thumbDisplay;
                else if (IMAGE_EXTS.contains(f.ext))        imgSrc = fileHref;
                else                                         imgSrc = placeholderSvg();

                String extBadge  = f.ext.isEmpty() ? "FILE" : f.ext.toUpperCase();
                String nameBadge = truncateName(f.originalFilename, 18) + "."
                                   + (f.ext.isEmpty() ? "file" : f.ext);
                tiles.append(tile(fileHref, htmlEsc(f.originalFilename), imgSrc,
                        extBadge, nameBadge, buildMetaHtml(f), delay));
            }

            String pLabel = totalPages > 1 ? " – Page " + page + " of " + totalPages : "";
            String cLabel = total == 1 ? "1 file" : total + " files";
            String rLabel = totalPages > 1
                    ? "Showing " + startNum + "–" + endNum + " of " + total + " files"
                    : "Total of " + cLabel;

            String sidebar = buildSidebar(sidebarCats, null, inPages ? "../" : "", true);
            String pagNav  = renderPagination(page, totalPages, startIdx, true, page);

            String html = pageShell(
                    "SiteBuilder" + pLabel,
                    buildRootBody(pLabel, rLabel, tiles.toString(), pagNav, sidebar));

            if (page == 1) writeFile(baseDir.resolve("index.html"), html);
            else           writeFile(pagesDir.resolve("index_" + page + ".html"), html);
        }
        System.out.println("  ? root index ? " + total + " files, " + totalPages + " page(s)");
    }

    // -- Deduplication helper --------------------------------------------------

    static List<FileEntry> collectUniqueEntries(Map<String, List<FileEntry>> tagMap,
                                                 List<Path> fileList) {
        Map<String, FileEntry> byName = new LinkedHashMap<>();
        for (List<FileEntry> entries : tagMap.values())
            for (FileEntry e : entries)
                byName.put(e.fileName, e);

        List<FileEntry> result = new ArrayList<>();
        for (Path p : fileList) {
            String name = p.getFileName().toString();
            if (byName.containsKey(name)) result.add(byName.get(name));
        }
        return result;
    }

    // -- HTML assembly ---------------------------------------------------------

    static String pageShell(String title, String body) {
        return "<!doctype html>\n<html lang=\"en\">\n<head>\n"
             + "<meta charset=\"utf-8\" />\n"
             + "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\" />\n"
             + "<title>" + title + "</title>\n"
             + sharedStyles() + "\n"
             + "</head>\n<body>\n"
             + topBar()
             + body
             + "\n<footer>&copy; SiteBuilder</footer>\n"
             + "</body>\n</html>";
    }

    static String topBar() {
        return "<header class=\"top-bar\">\n"
             + "  <a class=\"site-name\" href=\"index.html\">SiteBuilder</a>\n"
             + "  <form class=\"search-form\" onsubmit=\"doSearch(event)\" autocomplete=\"off\">\n"
             + "    <input id=\"q\" class=\"search-input\" type=\"search\""
             + " placeholder=\"Search category…\" aria-label=\"Search category\" />\n"
             + "    <button class=\"search-btn\" type=\"submit\">Go</button>\n"
             + "  </form>\n"
             + "</header>\n"
             + "<script>\n"
             + "function doSearch(e){\n"
             + "  e.preventDefault();\n"
             + "  var q=(document.getElementById('q').value||'').trim().toLowerCase()\n"
             + "         .replace(/\\s+/g,'-').replace(/[^a-z0-9\\-]/g,'').replace(/-+/g,'-')\n"
             + "         .replace(/^-|-$/g,'');\n"
             + "  if(!q) return;\n"
             + "  var root=location.href.replace(/\\/categories\\/.*$/,'')\n"
             + "                        .replace(/\\/pages\\/.*$/,'');\n"
             + "  root=root.replace(/\\/index[^/]*$/,'');\n"
             + "  if(root.charAt(root.length-1)==='/') root=root.slice(0,-1);\n"
             + "  window.location.href=root+'/categories/'+q+'/index.html';\n"
             + "}\n"
             + "</script>\n";
    }

    static String buildSidebar(List<CategoryInfo> cats, String activeCat,
                                String pathPrefix, boolean isRoot) {
        StringBuilder sb = new StringBuilder();
        sb.append("<aside class=\"sidebar\">\n")
          .append("  <p class=\"sidebar-title\">Categories</p>\n")
          .append("  <ul class=\"sidebar-list\">\n");
        for (CategoryInfo c : cats) {
            String  display = toDisplayName(c.name) + " (" + c.count + ")";
            String  href    = pathPrefix + "categories/" + htmlEsc(c.name) + "/index.html";
            boolean active  = c.name.equals(activeCat);
            sb.append("    <li><a href=\"").append(href).append("\"")
              .append(active ? " class=\"active\"" : "")
              .append(">").append(htmlEsc(display)).append("</a></li>\n");
        }
        sb.append("  </ul>\n</aside>\n");
        return sb.toString();
    }

    static String buildRootBody(String pageLabel, String rangeLabel,
                                 String tilesHtml, String pagination, String sidebar) {
        return "<div class=\"layout\">\n"
             + "<main>\n"
             + "  <section aria-label=\"All files\">\n"
             + "    <div class=\"grid\">\n"
             + tilesHtml
             + "    </div>\n"
             + "  </section>\n"
             + "  " + pagination
             + "  <section class=\"hero\">\n"
             + "    <p class=\"eyebrow\">Collection</p>\n"
             + "    <h1>Files</h1>\n"
             + "    <p class=\"lede\">" + htmlEsc(rangeLabel) + "</p>\n"
             + "    <div class=\"rule\"></div>\n"
             + "  </section>\n"
             + "</main>\n"
             + sidebar
             + "</div>\n";
    }

    static String buildCategoryBody(String displayName, String pageLabel, String rangeLabel,
                                     String countLabel, String tilesHtml, String pagination,
                                     String backLink, String sidebar) {
        return "<nav class=\"back-bar\" aria-label=\"Breadcrumb\">\n"
             + "  <a href=\"" + backLink + "\">"
             + "<svg width=\"14\" height=\"14\" viewBox=\"0 0 14 14\" fill=\"none\""
             + " stroke=\"currentColor\" stroke-width=\"1.8\""
             + " stroke-linecap=\"round\" stroke-linejoin=\"round\">"
             + "<path d=\"M9 11L5 7l4-4\"/></svg> Files</a>\n"
             + "  <span class=\"sep\">/</span>\n"
             + "  <span class=\"current\">" + htmlEsc(displayName) + "</span>\n"
             + "</nav>\n"
             + "<div class=\"layout\">\n"
             + "<main>\n"
             + "  <section aria-label=\"Files in " + htmlEsc(displayName) + "\">\n"
             + "    <div class=\"grid\">\n"
             + tilesHtml
             + "    </div>\n"
             + "  </section>\n"
             + "  " + pagination
             + "  <section class=\"hero\">\n"
             + "    <p class=\"eyebrow\">Category</p>\n"
             + "    <h1>" + htmlEsc(displayName) + "</h1>\n"
             + "    <p class=\"lede\">" + htmlEsc(rangeLabel) + "</p>\n"
             + "    <div class=\"rule\"></div>\n"
             + "  </section>\n"
             + "</main>\n"
             + sidebar
             + "</div>\n";
    }

    static String tile(String href, String label, String imgSrc,
                       String extBadge, String nameBadge, String metaHtml, int delay) {
        return "      <a class=\"tile\" href=\"" + href + "\""
             + " target=\"_blank\" rel=\"noopener noreferrer\""
             + " aria-label=\"Open: " + label + "\""
             + " style=\"animation-delay:" + delay + "ms\">\n"
             + "        <img loading=\"lazy\" alt=\"" + label + "\" src=\"" + imgSrc + "\" />\n"
             + "        <span class=\"label\">" + label + "</span>\n"
             + "        <span class=\"file-badge\" title=\"" + htmlEsc(nameBadge) + "\">"
             +              htmlEsc(nameBadge) + "</span>\n"
             + metaHtml
             + "      </a>\n\n";
    }

    static String buildMetaHtml(FileEntry f) {
        if (f.meta.isEmpty()) return "";
        StringBuilder sb = new StringBuilder("        <div class=\"meta-overlay\">\n");
        for (Map.Entry<String, String> me : f.meta.entrySet()) {
            sb.append("          <div class=\"meta-row\">")
              .append("<span class=\"meta-key\">").append(htmlEsc(toDisplayName(me.getKey()))).append("</span>")
              .append("<span class=\"meta-val\">").append(htmlEsc(me.getValue())).append("</span>")
              .append("</div>\n");
        }
        sb.append("        </div>\n");
        return sb.toString();
    }

    // -- Pagination ------------------------------------------------------------

    static String renderPagination(int current, int total, int startIdx,
                                   boolean isRoot, int curPage) {
        if (total <= 1) return "";

        String chevL = "<svg width=\"13\" height=\"13\" viewBox=\"0 0 14 14\" fill=\"none\""
                + " stroke=\"currentColor\" stroke-width=\"1.9\" stroke-linecap=\"round\""
                + " stroke-linejoin=\"round\"><path d=\"M9 11L5 7l4-4\"/></svg>";
        String chevR = "<svg width=\"13\" height=\"13\" viewBox=\"0 0 14 14\" fill=\"none\""
                + " stroke=\"currentColor\" stroke-width=\"1.9\" stroke-linecap=\"round\""
                + " stroke-linejoin=\"round\"><path d=\"M5 3l4 4-4 4\"/></svg>";

        int blockStart0 = (startIdx / PAG_BLOCK) * PAG_BLOCK;
        int blockEnd0   = blockStart0 + PAG_BLOCK - 1;

        int firstPageInBlock = blockStart0 / PER_PAGE + 1;
        int lastPageInBlock  = Math.min(total, (blockEnd0 / PER_PAGE) + 1);

        boolean hasPrevBlock = firstPageInBlock > 1;
        boolean hasNextBlock = lastPageInBlock < total;

        StringBuilder out = new StringBuilder("<nav class=\"pagination\" aria-label=\"Pagination\">\n");

        // Previous button
        if (current > 1)
            out.append("  <a href=\"").append(pageHref(current - 1, isRoot, curPage))
               .append("\" aria-label=\"Previous\">").append(chevL).append(" Prev</a>\n");
        else
            out.append("  <span class=\"pg-disabled\">").append(chevL).append(" Prev</span>\n");

        // Block-back jump
        if (hasPrevBlock) {
            int jumpPage  = firstPageInBlock - 1;
            int jumpLabel = (jumpPage - 1) * PER_PAGE + 1;
            out.append("  <a class=\"pg-block-jump\" href=\"")
               .append(pageHref(jumpPage, isRoot, curPage))
               .append("\" aria-label=\"Previous block, entry ").append(jumpLabel).append("\">")
               .append("&laquo; ").append(jumpLabel).append("</a>\n")
               .append("  <span class=\"pg-ellipsis\">&hellip;</span>\n");
        }

        // Pages within current block
        int rendered = 0;
        Integer prevP = null;
        for (int p = 1; p <= total && rendered < PAG_BLOCK; p++) {
            int firstIdx0 = (p - 1) * PER_PAGE;
            if (firstIdx0 < blockStart0 || firstIdx0 > blockEnd0) continue;
            int entryLabel = firstIdx0 + 1;

            if (prevP != null && p - prevP > 1)
                out.append("  <span class=\"pg-ellipsis\">&hellip;</span>\n");

            if (p == current)
                out.append("  <span class=\"pg-current\" aria-current=\"page\">")
                   .append(entryLabel).append("</span>\n");
            else
                out.append("  <a href=\"").append(pageHref(p, isRoot, curPage))
                   .append("\" aria-label=\"Entry ").append(entryLabel).append("\">")
                   .append(entryLabel).append("</a>\n");

            prevP = p;
            rendered++;
        }

        // Block-forward jump
        if (hasNextBlock) {
            int jumpPage  = lastPageInBlock + 1;
            int jumpLabel = (jumpPage - 1) * PER_PAGE + 1;
            out.append("  <span class=\"pg-ellipsis\">&hellip;</span>\n")
               .append("  <a class=\"pg-block-jump\" href=\"")
               .append(pageHref(jumpPage, isRoot, curPage))
               .append("\" aria-label=\"Next block, entry ").append(jumpLabel).append("\">")
               .append(jumpLabel).append(" &raquo;</a>\n");
        }

        // Next button
        if (current < total)
            out.append("  <a href=\"").append(pageHref(current + 1, isRoot, curPage))
               .append("\" aria-label=\"Next\">Next ").append(chevR).append("</a>\n");
        else
            out.append("  <span class=\"pg-disabled\">Next ").append(chevR).append("</span>\n");

        out.append("</nav>\n");
        return out.toString();
    }

    static String pageHref(int target, boolean isRoot, int currentPage) {
        if (!isRoot) return target == 1 ? "index.html" : "index_" + target + ".html";
        if (currentPage == 1)
            return target == 1 ? "index.html" : "pages/index_" + target + ".html";
        else
            return target == 1 ? "../index.html" : "index_" + target + ".html";
    }

    // -- Tag splitting ---------------------------------------------------------

    static final Set<String> EXT_BLOCKLIST = new HashSet<>(Arrays.asList(
        "mkv","avi","mov","wmv","flv","webm","m4v","mpg","mpeg","ts","m2ts",
        "mp3","aac","ogg","flac","wav","wma","m4a","opus","aiff","alac",
        "jpg","jpeg","png","gif","webp","avif","bmp","tiff","tif","svg","ico","heic","heif","raw",
        "pdf","doc","docx","xls","xlsx","ppt","pptx","txt","csv","xml","json","zip","rar",
        "tar","gz","bz2","7z","iso","dmg","exe","apk","torrent","nfo","srt","sub","ass","vtt"
    ));

    static List<String> splitIntoTags(String name) {
        Set<String> seen = new LinkedHashSet<>();
        for (String part : name.split("[^a-zA-Z]+")) {
            String tag = part.trim().toLowerCase();
            if (tag.length() <= 2) continue;
            if (tag.matches(".*\\d.*")) continue;
            if (EXT_BLOCKLIST.contains(tag)) continue;
            tag = tag.replaceAll("[^a-z]", "-").replaceAll("-+", "-").replaceAll("(^-|-$)", "");
            if (tag.isEmpty() || tag.length() <= 2) continue;
            seen.add(tag);
            if (seen.size() >= MAX_TAGS) break;
        }
        if (seen.isEmpty()) seen.add("uncategorized");
        return new ArrayList<>(seen);
    }

    // -- Styles ----------------------------------------------------------------

    static String sharedStyles() {
        return "<style>\n"

            + "  :root{\n"
            + "    --bg:#fafbfc;--fg:#0f172a;--muted:#64748b;\n"
            + "    --border:#e8ecf1;--primary:#3b82f6;--surface:#fff;\n"
            + "    --top:52px;\n"
            + "  }\n"
            + "  *,*::before,*::after{box-sizing:border-box;margin:0;padding:0;}\n"
            + "  html,body{background:var(--bg);color:var(--fg);"
            + "font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;"
            + "-webkit-font-smoothing:antialiased;min-height:100vh;display:flex;flex-direction:column;}\n"

            // -- Top bar --
            + "  .top-bar{\n"
            + "    position:sticky;top:0;z-index:100;\n"
            + "    height:var(--top);\n"
            + "    display:flex;align-items:center;gap:12px;\n"
            + "    padding:0 20px;\n"
            + "    background:var(--surface);\n"
            + "    border-bottom:1px solid var(--border);\n"
            + "  }\n"
            + "  .site-name{\n"
            + "    font-size:13px;font-weight:700;color:var(--fg);\n"
            + "    text-decoration:none;white-space:nowrap;flex-shrink:0;\n"
            + "  }\n"
            + "  .search-form{display:flex;gap:0;flex:1;max-width:400px;margin-left:auto;}\n"
            + "  .search-input{\n"
            + "    flex:1;height:32px;padding:0 10px;\n"
            + "    border:1px solid var(--border);border-right:none;\n"
            + "    border-radius:4px 0 0 4px;\n"
            + "    font-size:13px;color:var(--fg);background:var(--bg);\n"
            + "    outline:none;transition:border-color .2s;\n"
            + "  }\n"
            + "  .search-input:focus{border-color:var(--primary);}\n"
            + "  .search-btn{\n"
            + "    height:32px;padding:0 14px;\n"
            + "    background:var(--primary);color:#fff;\n"
            + "    border:1px solid var(--primary);\n"
            + "    border-radius:0 4px 4px 0;\n"
            + "    font-size:13px;font-weight:600;\n"
            + "    cursor:pointer;transition:opacity .2s;\n"
            + "  }\n"
            + "  .search-btn:hover{opacity:.85;}\n"

            // -- Layout --
            + "  .layout{display:flex;flex:1;min-height:0;align-items:flex-start;}\n"
            + "  main{flex:1;min-width:0;}\n"

            // -- Sidebar --
            + "  .sidebar{\n"
            + "    width:200px;flex-shrink:0;\n"
            + "    position:sticky;top:var(--top);\n"
            + "    max-height:calc(100vh - var(--top));\n"
            + "    overflow-y:auto;\n"
            + "    padding:16px 12px;\n"
            + "    border-left:1px solid var(--border);\n"
            + "    background:var(--surface);\n"
            + "  }\n"
            + "  @media(max-width:767px){.sidebar{display:none;}}\n"
            + "  .sidebar-title{\n"
            + "    font-size:9px;font-weight:700;letter-spacing:.14em;\n"
            + "    text-transform:uppercase;color:var(--muted);\n"
            + "    margin-bottom:10px;padding:0 4px;\n"
            + "  }\n"
            + "  .sidebar-list{list-style:none;}\n"
            + "  .sidebar-list li{margin:0;}\n"
            + "  .sidebar-list a{\n"
            + "    display:block;padding:5px 8px;\n"
            + "    font-size:12px;color:var(--muted);\n"
            + "    text-decoration:none;border-radius:4px;\n"
            + "    white-space:nowrap;overflow:hidden;text-overflow:ellipsis;\n"
            + "    transition:background .15s,color .15s;\n"
            + "  }\n"
            + "  .sidebar-list a:hover,.sidebar-list a.active{\n"
            + "    background:var(--border);color:var(--fg);\n"
            + "  }\n"
            + "  .sidebar-list a.active{font-weight:600;}\n"

            // -- Grid --
            + "  .grid{display:grid;grid-template-columns:repeat(2,1fr);gap:3px;width:100%;}\n"
            + "  @media(min-width:580px){.grid{grid-template-columns:repeat(3,1fr);}}\n"
            + "  @media(min-width:768px){.grid{grid-template-columns:repeat(4,1fr);}}\n"
            + "  @media(min-width:1024px){.grid{grid-template-columns:repeat(5,1fr);}}\n"

            // -- Tile --
            + "  .tile{\n"
            + "    position:relative;display:block;aspect-ratio:1/1;\n"
            + "    overflow:hidden;background:var(--border);\n"
            + "    outline:none;text-decoration:none;cursor:pointer;\n"
            + "    animation:fadeUp .45s ease both;\n"
            + "  }\n"
            + "  .tile:focus-visible{box-shadow:0 0 0 2px var(--bg),0 0 0 4px var(--primary);}\n"
            + "  .tile img{width:100%;height:100%;object-fit:cover;display:block;"
            + "transition:transform .55s cubic-bezier(.25,.46,.45,.94);}\n"
            + "  .tile:hover img{transform:scale(1.06);}\n"
            + "  .tile::after{content:'';position:absolute;inset:0;"
            + "background:rgba(15,23,42,0);transition:background .3s;pointer-events:none;}\n"
            + "  .tile:hover::after{background:rgba(15,23,42,.08);}\n"

            + "  .tile .label{\n"
            + "    position:absolute;bottom:0;left:0;right:0;\n"
            + "    padding:24px 10px 10px;\n"
            + "    background:linear-gradient(to top,rgba(15,23,42,.7),transparent);\n"
            + "    color:#fff;font-size:11px;font-weight:500;letter-spacing:.03em;\n"
            + "    opacity:0;transform:translateY(4px);\n"
            + "    transition:opacity .3s,transform .3s;pointer-events:none;\n"
            + "    white-space:nowrap;overflow:hidden;text-overflow:ellipsis;\n"
            + "  }\n"
            + "  .tile:hover .label{opacity:1;transform:translateY(0);}\n"

            + "  .file-badge{\n"
            + "    position:absolute;top:6px;right:6px;\n"
            + "    max-width:calc(100% - 12px);\n"
            + "    background:rgba(15,23,42,.72);backdrop-filter:blur(4px);\n"
            + "    color:#fff;font-size:9px;font-weight:700;\n"
            + "    letter-spacing:.06em;\n"
            + "    padding:2px 6px;border-radius:3px;\n"
            + "    white-space:nowrap;overflow:hidden;text-overflow:ellipsis;\n"
            + "    opacity:1;pointer-events:none;\n"
            + "    transition:opacity .2s;\n"
            + "  }\n"
            + "  .tile:hover .file-badge{opacity:.85;}\n"

            + "  .meta-overlay{\n"
            + "    position:absolute;inset:0;background:rgba(15,23,42,.85);\n"
            + "    display:flex;flex-direction:column;justify-content:flex-end;\n"
            + "    padding:10px;gap:4px;\n"
            + "    opacity:0;transition:opacity .3s;pointer-events:none;overflow:hidden;\n"
            + "  }\n"
            + "  .tile:hover .meta-overlay{opacity:1;}\n"
            + "  .meta-row{display:flex;gap:4px;min-width:0;}\n"
            + "  .meta-key{color:rgba(255,255,255,.55);font-size:9px;font-weight:700;"
            + "letter-spacing:.08em;text-transform:uppercase;white-space:nowrap;flex-shrink:0;}\n"
            + "  .meta-val{color:#fff;font-size:10px;white-space:nowrap;overflow:hidden;"
            + "text-overflow:ellipsis;}\n"

            // -- Breadcrumb --
            + "  .back-bar{\n"
            + "    display:flex;align-items:center;gap:8px;\n"
            + "    padding:12px 20px;border-bottom:1px solid var(--border);\n"
            + "    background:var(--surface);\n"
            + "  }\n"
            + "  .back-bar a{display:inline-flex;align-items:center;gap:6px;"
            + "font-size:13px;font-weight:500;color:var(--muted);"
            + "text-decoration:none;transition:color .2s;}\n"
            + "  .back-bar a:hover{color:var(--fg);}\n"
            + "  .back-bar .sep{font-size:13px;color:var(--border);}\n"
            + "  .back-bar .current{font-size:13px;font-weight:500;color:var(--fg);}\n"

            // -- Hero --
            + "  .hero{max-width:48rem;margin:0 auto;padding:56px 24px;text-align:center;}\n"
            + "  .eyebrow{font-size:11px;font-weight:600;letter-spacing:.2em;"
            + "text-transform:uppercase;color:var(--primary);}\n"
            + "  h1{margin-top:14px;font-size:clamp(32px,5vw,52px);"
            + "font-weight:400;letter-spacing:-.02em;line-height:1.05;}\n"
            + "  .lede{margin-top:12px;font-size:16px;color:var(--muted);font-weight:300;}\n"
            + "  .rule{margin:24px auto 0;width:48px;height:1px;background:var(--border);}\n"

            // -- Pagination --
            + "  .pagination{display:flex;align-items:center;justify-content:center;"
            + "flex-wrap:wrap;gap:6px;padding:36px 24px 52px;}\n"
            + "  .pagination a,.pagination span{display:inline-flex;align-items:center;"
            + "justify-content:center;min-width:36px;height:36px;padding:0 10px;"
            + "border-radius:4px;font-size:13px;font-weight:500;text-decoration:none;"
            + "transition:background .18s,color .18s,border-color .18s;"
            + "border:1px solid var(--border);color:var(--muted);"
            + "background:var(--surface);gap:5px;white-space:nowrap;}\n"
            + "  .pagination a:hover{background:var(--fg);color:var(--bg);border-color:var(--fg);}\n"
            + "  .pagination .pg-current{background:var(--fg);color:var(--bg);"
            + "border-color:var(--fg);cursor:default;}\n"
            + "  .pagination .pg-ellipsis{border-color:transparent;background:transparent;"
            + "cursor:default;color:var(--border);min-width:20px;}\n"
            + "  .pagination .pg-disabled{opacity:.32;pointer-events:none;cursor:default;}\n"
            + "  .pagination .pg-block-jump{font-size:11px;color:var(--primary);"
            + "border-color:var(--primary);}\n"
            + "  .pagination .pg-block-jump:hover{background:var(--primary);color:#fff;}\n"

            // -- Footer --
            + "  footer{text-align:center;padding:20px;font-size:12px;"
            + "color:var(--border);border-top:1px solid var(--border);}\n"

            // -- Animation --
            + "  @keyframes fadeUp{"
            + "from{opacity:0;transform:translateY(12px);}to{opacity:1;transform:translateY(0);}}\n"

            + "</style>\n";
    }

    // -- Page splitting helpers ------------------------------------------------

    static List<List<FileEntry>> splitIntoPages(List<FileEntry> entries) {
        List<List<FileEntry>> pages = new ArrayList<>();
        List<FileEntry> cur = new ArrayList<>();
        long sz = 0;
        for (FileEntry e : entries) {
            long est = estimateTile(e);
            if (!cur.isEmpty() && (cur.size() >= PER_PAGE || sz + est > MAX_PAGE_KB)) {
                pages.add(cur);
                cur = new ArrayList<>();
                sz  = 0;
            }
            cur.add(e);
            sz += est;
        }
        if (!cur.isEmpty()) pages.add(cur);
        if (pages.isEmpty()) pages.add(new ArrayList<FileEntry>());
        return pages;
    }

    static long estimateTile(FileEntry e) {
        long base = 300L;
        for (Map.Entry<String, String> me : e.meta.entrySet())
            base += me.getKey().length() + me.getValue().length() + 40;
        return base;
    }

    static int countBefore(List<List<FileEntry>> pages, int idx) {
        int n = 0;
        for (int i = 0; i < idx; i++) n += pages.get(i).size();
        return n;
    }

    // -- JSON parser -----------------------------------------------------------

    static Map<String, String> parseSimpleJson(String json) {
        Map<String, String> map = new LinkedHashMap<>();
        json = json.trim();
        if (json.startsWith("{")) json = json.substring(1);
        if (json.endsWith("}"))   json = json.substring(0, json.length() - 1);
        int i = 0;
        while (i < json.length()) {
            while (i < json.length() && (json.charAt(i) == ',' || Character.isWhitespace(json.charAt(i)))) i++;
            if (i >= json.length()) break;
            if (json.charAt(i) != '"') { i++; continue; }
            int ks = i + 1; i = nextQ(json, ks); if (i < 0) break;
            String key = unesc(json.substring(ks, i)); i++;
            while (i < json.length() && (json.charAt(i) == ':' || Character.isWhitespace(json.charAt(i)))) i++;
            if (i >= json.length()) break;
            char c = json.charAt(i);
            if (c == '"') {
                int vs = i + 1; i = nextQ(json, vs); if (i < 0) break;
                map.put(key, unesc(json.substring(vs, i))); i++;
            } else if (c == '{' || c == '[') {
                char cl = c == '{' ? '}' : ']'; int d = 1; i++;
                while (i < json.length() && d > 0) {
                    char ch = json.charAt(i);
                    if (ch == c) d++; else if (ch == cl) d--;
                    i++;
                }
            } else {
                int s = i;
                while (i < json.length() && json.charAt(i) != ',' && json.charAt(i) != '}') i++;
                map.put(key, json.substring(s, i).trim());
            }
        }
        return map;
    }

    static int nextQ(String s, int from) {
        for (int i = from; i < s.length(); i++)
            if (s.charAt(i) == '"' && (i == 0 || s.charAt(i - 1) != '\\')) return i;
        return -1;
    }

    static String unesc(String s) {
        return s.replace("\\\"", "\"").replace("\\\\", "\\").replace("\\/", "/")
                .replace("\\n", "\n").replace("\\r", "\r").replace("\\t", "\t");
    }

    // -- Small utilities -------------------------------------------------------

    static String getBaseName(String filename) {
        int dot = filename.lastIndexOf('.');
        return dot > 0 ? filename.substring(0, dot) : filename;
    }

    static String getExtension(String filename) {
        int dot = filename.lastIndexOf('.');
        return (dot >= 0 && dot < filename.length() - 1) ? filename.substring(dot + 1) : "";
    }

    // Alias kept for HTML-building code that uses the shorter names
    static String stem(String f) { return getBaseName(f); }
    static String ext(String f)  { return getExtension(f); }

    static String isoTimestamp(long epochMillis) {
        SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ssXXX");
        sdf.setTimeZone(TimeZone.getDefault());
        return sdf.format(new Date(epochMillis));
    }

    static String toDisplayName(String slug) {
        StringBuilder sb = new StringBuilder();
        for (String w : slug.replace("-", " ").replace("_", " ").split("\\s+")) {
            if (w.isEmpty()) continue;
            if (sb.length() > 0) sb.append(' ');
            sb.append(Character.toUpperCase(w.charAt(0)));
            if (w.length() > 1) sb.append(w.substring(1));
        }
        return sb.toString();
    }

    static String truncateName(String name, int maxLen) {
        if (name == null || name.length() <= maxLen) return name == null ? "" : name;
        return name.substring(0, maxLen - 1) + "…";
    }

    static String htmlEsc(String s) {
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
                .replace("\"", "&quot;").replace("'", "&#39;");
    }

    static String placeholderSvg() {
        return "data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='400' height='400'"
             + " viewBox='0 0 400 400'%3E%3Crect width='400' height='400' fill='%23e8ecf1'/%3E"
             + "%3Cg fill='%2394a3b8'%3E%3Crect x='155' y='130' width='90' height='110' rx='6'/%3E"
             + "%3Crect x='170' y='155' width='60' height='8' rx='3'/%3E"
             + "%3Crect x='170' y='172' width='45' height='8' rx='3'/%3E"
             + "%3Crect x='170' y='189' width='52' height='8' rx='3'/%3E"
             + "%3Crect x='170' y='206' width='38' height='8' rx='3'/%3E"
             + "%3C/g%3E%3C/svg%3E";
    }

    static int countUniqueFiles(Map<String, List<FileEntry>> m) {
        Set<String> s = new HashSet<>();
        for (List<FileEntry> l : m.values()) for (FileEntry e : l) s.add(e.fileName);
        return s.size();
    }

    static void writeFile(Path path, String content) throws IOException {
        Files.write(path, content.getBytes(StandardCharsets.UTF_8));
    }

    // -- Data classes ----------------------------------------------------------

    static class FileEntry {
        final String fileName, stem, ext, originalFilename, thumbSrc;
        final Map<String, String> meta;
        final boolean isVideo;

        FileEntry(String fn, String st, String ex, Map<String, String> me,
                  String of, boolean iv, String th) {
            fileName = fn; stem = st; ext = ex; meta = me;
            originalFilename = of; isVideo = iv; thumbSrc = th;
        }
    }

    static class CategoryInfo {
        final String name;
        final int count;
        CategoryInfo(String n, int c) { name = n; count = c; }
    }
}