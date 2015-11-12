package com.contrastsecurity.foil;

import java.lang.instrument.ClassFileTransformer;
import java.lang.instrument.IllegalClassFormatException;
import java.security.ProtectionDomain;

import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.ClassWriter;

/**
 * Just transform a single class - java.io.ObjectInputStream. Let
 * the user know if there are any problems doing that via sysout.
 */
public class FoilTransformer implements ClassFileTransformer {

	public byte[] transform(ClassLoader cl, String className, Class<?> parentClass, ProtectionDomain pd, byte[] originalBytecode) throws IllegalClassFormatException {
		byte[] transformedBytecode = null;
		if("java/io/ObjectInputStream".equals(className)) {
			transformedBytecode = weavePatch(originalBytecode);
		}
		return transformedBytecode;
	}

	private byte[] weavePatch(byte[] originalBytecode) {
		byte[] transformedBytecode = null;
		try {
			ClassReader reader = new ClassReader(originalBytecode);
			ClassWriter writer = new ClassWriter(ClassWriter.COMPUTE_FRAMES | ClassWriter.COMPUTE_MAXS);
			ClassVisitor visitor = new ObjectInputStreamVisitor(writer);
			reader.accept(visitor, ClassReader.EXPAND_FRAMES);
			transformedBytecode = writer.toByteArray();
			FoilAgent.out("Protection against deserialization attacks added to java.io.ObjectInputStream");
		} catch (Throwable t) {
			FoilAgent.out("Problem instrumenting java.io.ObjectInputStream -- no deserialization protection in place");
			t.printStackTrace();
		}
		return transformedBytecode;
	}
}
