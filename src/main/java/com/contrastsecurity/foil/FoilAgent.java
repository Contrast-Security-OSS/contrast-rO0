package com.contrastsecurity.foil;

import java.io.IOException;
import java.lang.instrument.ClassFileTransformer;
import java.lang.instrument.Instrumentation;

/**
 * Install a ClassFileTransformer to instrument ObjectInputStream.
 */
public class FoilAgent {
	
	public static void premain(String args, Instrumentation inst) throws IOException {
		setup(args, inst);
	}
	
	public static void agentmain(String args, Instrumentation inst) throws IOException {
		setup(args, inst);
	}

	private static void setup(String args, Instrumentation inst) {
		ClassFileTransformer xform = new FoilTransformer();
		inst.addTransformer(xform);
	}
	
	public static void out(String msg) {
		String quiet = System.getProperty("foil.quiet");
		if(quiet == null || !"true".equalsIgnoreCase(quiet)) {
			System.out.println("[deserial-foil] " + msg);
		}
	}
	
	public static void main(String[] args) {
		FoilAgent.out("To use deserial-foil, add it as a Java agent with the following flag: ");
		FoilAgent.out("  -javaagent:/path/to/deserial-foil.jar");
	}
}
