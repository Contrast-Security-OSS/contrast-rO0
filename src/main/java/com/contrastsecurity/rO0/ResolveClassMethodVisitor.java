package com.contrastsecurity.rO0;

import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
import org.objectweb.asm.commons.AdviceAdapter;
import org.objectweb.asm.commons.Method;

public class ResolveClassMethodVisitor extends AdviceAdapter {

	protected ResolveClassMethodVisitor(MethodVisitor mv, int access, String name, String desc) {
		super(Opcodes.ASM5, mv, access, name, desc);
	}

	/**
	 * Fire off our sensor at the beginning of ObjectInputStream#resolveClass(java.io.ObjectStreamClass).
	 */
	@Override
	protected void onMethodEnter() {
		Type type = Type.getType(ResolveClassController.class);
		Method method = new Method("onResolveClass", "(Ljava/io/ObjectStreamClass;)V");
		loadArg(0);
		invokeStatic(type,method);
	}
}
