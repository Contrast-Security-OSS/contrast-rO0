package com.contrastsecurity.rO0;

import java.io.IOException;
import java.lang.instrument.ClassFileTransformer;
import java.lang.instrument.Instrumentation;

/**
 * Install a ClassFileTransformer to instrument ObjectInputStream.
 */
public class RO0Agent {
	
	public static void premain(String args, Instrumentation inst) throws IOException {
		setup(args, inst);
	}
	
	public static void agentmain(String args, Instrumentation inst) throws IOException {
		setup(args, inst);
	}

	private static void setup(String args, Instrumentation inst) {
		ClassFileTransformer xform = new RO0Transformer();
		inst.addTransformer(xform);
	}
	
	public static void out(String msg) {
		String quiet = System.getProperty("rO0.quiet");
		if(quiet == null || !"true".equalsIgnoreCase(quiet)) {
			System.out.println("[contrast-rO0] " + msg);
		}
	}
	
	public static void main(String[] args) {
		System.out.println("********************************************************************");
		System.out.println("* contrast-rO0 - the hotpatching agent for deserialization attacks *");
		System.out.println("********************************************************************");
		System.out.println();
		System.out.println("To use contrast-rO0, add it as a Java agent with the following flag: ");
		System.out.println("  -javaagent:/path/to/contrast-rO0.jar");
		System.out.println();
	}
}
