package com.contrastsecurity.rO0;

import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.lang.instrument.ClassFileTransformer;
import java.lang.instrument.Instrumentation;
import java.util.Properties;

/**
 * Install a ClassFileTransformer to instrument ObjectInputStream.
 */
public class RO0Agent {
	
	public static RO0Config config = new RO0Config();
	
	// added to make unit testing / prerequisite verification easier
	public static boolean loaded = false;

	/**
	 * The location where we'll write our output.  Defaults to System.out, but
	 * can be configured to go elsewhere.
	 */
	private static PrintStream out = System.out;

	/**
	 * configuration properties as passed in to premain and/or agentmain
	 */
	static private Properties properties = null;

	
	public static void premain(String args, Instrumentation inst) throws IOException {
		setup(args, inst);
	}
	
	public static void agentmain(String args, Instrumentation inst) throws IOException {
		setup(args, inst);
	}

	private static void setup(String args, Instrumentation inst) {
		properties = parseCommandLine(args);
		
		ClassFileTransformer xform = new RO0Transformer();
		inst.addTransformer(xform);
		readConfig(args);
	}
	
	private static void readConfig(String args) {
		
		
		String outfile = getProperty("rO0.outfile");

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
			String listfile = getProperty("rO0.lists");
			config.readConfig(listfile);
		} catch (FileNotFoundException e) {
			out("failed to read config file");
			out(e);
		}
		
		String _reporting     = getProperty("rO0.reporting");
		String _ignoreClasses = getProperty("rO0.ignoreClasses");
		String _ignoreStack   = getProperty("rO0.ignoreStack");
		String _whitelist     = getProperty("rO0.whitelist");
		String _blacklist     = getProperty("rO0.blacklist");
		debug("blacklist = " + _blacklist);
		
		/* Read configuration from the environment (see the README for details about how to set this
		 * stuff).  Default is that nothing is enabled.  
		 * 
		 * If it's null, it's not set, so it's disabled.  If it's not "true" it's not set as we expect
		 * so it's disabled.
		 */
		
		// This one is enabled by default, so the "null" is opposite. If it's present
		// it must be "true" to be enabled, but if it's not present, it's still true.
		boolean reportingEnabled   = ( _reporting     == null || _reporting.equals("true")  ); 
		
		// These are normal
		boolean classIgnoreEnabled = ( _ignoreClasses != null && _ignoreClasses.equals("true") );
		boolean stackIgnoreEnabled = ( _ignoreStack   != null && _ignoreStack.equals("true")   );
		boolean whitelistEnabled   = ( _whitelist     != null && _whitelist.equals("true")     );
		boolean blacklistEnabled   = ( _blacklist     != null && _blacklist.equals("true")     );
		
		config.setReporting(reportingEnabled);
		config.setClassFiltering(classIgnoreEnabled);
		config.setStackFiltering(stackIgnoreEnabled);
		config.setWhitelisting(whitelistEnabled);
		config.setBlacklisting(blacklistEnabled);
		
		debug("Configuration = " + config.toString());
		
		loaded = true;
	}
	
	
	/** 
	 * Reads the specified property from the properties object; if not found,
	 * checks the environment.
	 * 
	 * @param string the property to read
	 * @param properties the properties to check
	 * 
	 * @return the value as specified by the properties object; if it does not exist
	 *         in the properties object, the value as specified in the environment;
	 *         null if not found anywhere.
	 */
	private static String getProperty(String string) {
		if( properties == null ) {
			return null;
		}
		
		return properties.getProperty(string, System.getProperty(string));
	}

	private static Properties parseCommandLine(String args) {
		debug("parsing command line:" + args);
		Properties properties = new Properties();
		if( args == null ) return properties;

		// key value pairs separated by commas
		String[] pairs = args.split(",");
		for( String pair : pairs) {
			debug("kvpair = " + pair);
			if ( pair.length() == 0 ) continue;
			
			String[] key_value = pair.split(":");
			String key = key_value[0];
			String value = (key_value.length > 1) ? key_value[1] : "";
			properties.setProperty(key,  value);
			debug("Added key="+key+" value="+value);
		}
		
		debug("properties = " + properties);
		return properties;
	}

	public static void out(String msg) {
		String quiet = getProperty("rO0.quiet");
		if(quiet == null || !"true".equalsIgnoreCase(quiet)) {
			out.println("[contrast-rO0] " + msg);
		}
	}
	
	
	public static void out(Throwable t) {
		String veryQuiet = getProperty("rO0.quiet");
		String quiet = getProperty("rO0.noStackTraces");
		
		if( veryQuiet != null && "true".equalsIgnoreCase(veryQuiet) ) return;
		if( quiet     != null && "true".equalsIgnoreCase(quiet) ) return;

		t.printStackTrace(out);
	}
	
	public static void debug(String s) {
		String debug = getProperty("rO0.debug");
		if( debug != null && debug.equals("true") )
		{
			out.println("[contrast.rO0] DEBUG: " + s);
		}
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
