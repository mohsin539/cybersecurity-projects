import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.PrintWriter;

/**
 * REkt Ghidra post-script: decompile up to N functions to one pseudo-C file.
 * Invoked by rekt/application/ghidra.py via analyzeHeadless (consent-gated).
 * Output format is parsed by the bridge: "// ==== name @ addr" separators.
 */
public class ExportDecomp extends GhidraScript {

    private static final int MAX_FUNCTIONS = 500;
    private static final int PER_FUNCTION_TIMEOUT_S = 30;

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        String outPath = args.length > 0 ? args[0] : "decomp.c";

        DecompInterface di = new DecompInterface();
        di.openProgram(currentProgram);

        PrintWriter pw = new PrintWriter(new BufferedWriter(new FileWriter(outPath)));
        FunctionIterator it = currentProgram.getFunctionManager().getFunctions(true);
        int count = 0;
        while (it.hasNext() && count < MAX_FUNCTIONS) {
            Function f = it.next();
            DecompileResults res = di.decompileFunction(f, PER_FUNCTION_TIMEOUT_S, monitor);
            if (res != null && res.decompileCompleted() && res.getDecompiledFunction() != null) {
                pw.println("// ==== " + f.getName() + " @ " + f.getEntryPoint());
                pw.println(res.getDecompiledFunction().getC());
                count++;
            }
        }
        pw.close();
        di.dispose();
        println("ExportDecomp: wrote " + count + " functions to " + outPath);
    }
}
