package com.contrastsecurity.foil;

import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;

/**
 * 
 */
public class ObjectInputStreamVisitor extends ClassVisitor {

	public ObjectInputStreamVisitor(ClassVisitor cv) {
		super(Opcodes.ASM5, cv);
	}
	
	@Override
	public MethodVisitor visitMethod(int access, String name, String desc, String signature, String[] exceptions) {
		MethodVisitor mv = super.visitMethod(access, name, desc, signature, exceptions);
		if("resolveClass".equals(name) && "(Ljava/io/ObjectStreamClass;)Ljava/lang/Class;".equals(desc)) {
			mv = new ResolveClassMethodVisitor(mv, access, name, desc);
		}
		return mv;
	}

}
