// Authored QA adapter for the official BinExport 11.0.3 extension; never executes the target.
// @category PatchTrace.QA
import com.google.security.binexport.BinExportExporter;
import ghidra.app.script.GhidraScript;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;

public class ExportBinExport20261102 extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 2 || !args[1].matches("[0-9a-f]{64}")) {
            throw new IllegalArgumentException("Expected private output directory and SHA-256");
        }
        if (currentProgram == null || !args[1].equals(currentProgram.getExecutableSHA256())) {
            throw new IllegalStateException("Imported program SHA-256 differs from the authored artifact");
        }
        Path directory = Path.of(args[0]).toAbsolutePath();
        if (!Files.isDirectory(directory, LinkOption.NOFOLLOW_LINKS)) {
            throw new IllegalStateException("A private output directory is required");
        }
        Path output = directory.resolve("output.BinExport");
        if (Files.exists(output, LinkOption.NOFOLLOW_LINKS)) {
            throw new IllegalStateException("Export destination already exists");
        }
        Path stage = Files.createTempFile(directory, "export-", ".partial");
        // All three upstream options default false: no imagebase subtraction,
        // no mnemonic remapping, no namespace prefix. Identical on both sides.
        BinExportExporter exporter = new BinExportExporter();
        if (!exporter.export(stage.toFile(), currentProgram, null, monitor) || Files.size(stage) == 0) {
            throw new IllegalStateException("Exporter did not produce a complete file");
        }
        Files.createLink(output, stage); // Exclusive publication; never replaces a user path.
        Files.delete(stage);            // Failed stages remain available for diagnosis.
        println("PATCHTRACE_BINEXPORT_OK " + args[1]);
    }
}
