package com.contrastsecurity.rO0;

import java.io.ObjectStreamClass;

public class ResolveClassController {

	public static void onResolveClass(ObjectStreamClass streamClass) {
		String name = streamClass.getName();
		if(isLikelyExploitGadget(name)) {
			String message = "Likely exploit gadget encoutered during deserialization: " + name;
			RO0Agent.out(message);
			throw new SecurityException(message);
		}
	}

	private static boolean isLikelyExploitGadget(String name) {
		boolean isGadget = false;
		if(name.endsWith("org.apache.commons.collections.functors.InvokerTransformer")) {
			isGadget = true;
		} else if(name.endsWith("org.apache.commons.collections.functors.InstantiateTransformer")) {
			isGadget = true;
		} else if(name.endsWith("org.apache.commons.collections4.functors.InvokerTransformer")) {
			isGadget = true;
		} else if(name.endsWith("org.apache.commons.collections4.functors.InstantiateTransformer")) {
			isGadget = true;
		} else if(name.endsWith("org.codehaus.groovy.runtime.ConvertedClosure")) {
			isGadget = true;
		} else if(name.endsWith("org.codehaus.groovy.runtime.MethodClosure")) {
			isGadget = true;
		} else if (name.endsWith("org.springframework.beans.factory.ObjectFactory")) {
			isGadget = true;
		}
		return isGadget;
	}
	
}
