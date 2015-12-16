package com.contrastsecurity.rO0;

import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.lang.instrument.ClassFileTransformer;
import java.lang.instrument.Instrumentation;

/**
 * Install a ClassFileTransformer to instrument ObjectInputStream.
 */
public class RO0Agent {
	
	public static DeserialFoilConfig config = new DeserialFoilConfig();
	
	// added to make unit testing / prerequisite verification easier
	public static boolean loaded = false;

	/**
	 * The location where we'll write our output.  Defaults to System.out, but
	 * can be configured to go elsewhere.
	 */
	private static PrintStream out = System.out;
	
	public static void premain(String args, Instrumentation inst) throws IOException {
		setup(args, inst);
	}
	
	public static void agentmain(String args, Instrumentation inst) throws IOException {
		setup(args, inst);
	}

	private static void setup(String args, Instrumentation inst) {
		ClassFileTransformer xform = new RO0Transformer();
		inst.addTransformer(xform);
		readEnvironment();
	}
	
	private static void readEnvironment() {
		
		String outfile = System.getProperty("RO0.outfile");
		if( outfile != null && !outfile.equals("") ) {
			out("redirecting output to " + outfile);
			try {
				out = new PrintStream(new FileOutputStream(outfile));
			} catch (FileNotFoundException e) {
				out("failed to redirect output.  Sending output to System.out.");
				e.printStackTrace();
			}
		}

		try {
			config.readConfig(System.getProperty("rO0.lists"));
		} catch (FileNotFoundException e) {
			out("failed to read config file");
			out(e);
		}
		
		String _reporting     = System.getProperty("rO0.reporting");
		String _ignoreClasses = System.getProperty("rO0.ignoreClasses");
		String _ignoreStack   = System.getProperty("rO0.ignoreStack");
		String _whitelist     = System.getProperty("rO0.whitelist");
		String _blacklist     = System.getProperty("rO0.blacklist");
		
		/* Read configuration from the environment (see the README for details about how to set this
		 * stuff).  Default is that nothing is enabled.  
		 * 
		 * If it's null, it's not set, so it's disabled.  If it's not "true" it's not set as we expect
		 * so it's disabled.
		 */
		boolean reportingEnabled   = ( _reporting     != null && ! _reporting.equals("true")  ); // note: this one is enabled by default
		boolean classIgnoreEnabled = ( _ignoreClasses != null && _ignoreClasses.equals("true") );
		boolean stackIgnoreEnabled = ( _ignoreStack   != null && _ignoreStack.equals("true")   );
		boolean whitelistEnabled   = ( _whitelist     != null && _whitelist.equals("true")     );
		boolean blacklistEnabled   = ( _blacklist     != null && _blacklist.equals("true")     );
		
		config.setReporting(reportingEnabled);
		config.setClassFiltering(classIgnoreEnabled);
		config.setStackFiltering(stackIgnoreEnabled);
		config.setWhitelisting(whitelistEnabled);
		config.setBlacklisting(blacklistEnabled);
		
		loaded = true;
	}
	
	public static void out(String msg) {
		String quiet = System.getProperty("rO0.quiet");
		if(quiet == null || !"true".equalsIgnoreCase(quiet)) {
			out.println("[contrast-rO0] " + msg);
		}
	}
	
	
	public static void out(Throwable t) {
		String veryQuiet = System.getProperty("rO0.quiet");
		String quiet = System.getProperty("rO0.noStackTraces");
		
		if( veryQuiet != null && "true".equalsIgnoreCase(veryQuiet) ) return;
		if( quiet     != null && "true".equalsIgnoreCase(quiet) ) return;

		t.printStackTrace(System.out);
	}
	
	public static void main(String[] args) {
		out.println("********************************************************************");
		out.println("* contrast-rO0 - the hotpatching agent for deserialization attacks *");
		out.println("********************************************************************");
		out.println();
		out.println("To use contrast-rO0, add it as a Java agent with the following flag: ");
		out.println("  -javaagent:/path/to/contrast-rO0.jar");
		out.println();
	}
}
