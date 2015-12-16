package com.contrastsecurity.rO0;

import java.io.ObjectStreamClass;

public class ResolveClassController {

	/**
	 * This is invoked at the beginning of java.io.ObjectInputStream#resolveClass().
	 * @param streamClass the parameter passed to resolveClass()
	 */
	public static void onResolveClass(ObjectStreamClass streamClass) {
		String name = streamClass.getName();
		
		if( RO0Agent.config.isBlacklisted(name) ) {
			String message = "Likely exploit gadget encoutered during deserialization: " + name;
			RO0Agent.out(message);
			throw new SecurityException(message);			
		}
		
		if( ! RO0Agent.config.isWhitelisted(name))  {
			String message = "Non-whitelisted class found during deserialization: " + name;
			RO0Agent.out(message);
			throw new SecurityException(message);				
		}
		
		// LAST thing to do is report.  If something else failed, an exception would have been
		// thrown, and an error reported; we'd never get here; or if something was found on
		// an ignore list, we'd never get here.  Note that there are two ways to ignore stuff,
		// so that we don't get really noisy logging.  First is ignoring classes to be deserialized.
		// second is ignoring deserialization attempts with entries on the stack.
		if( ! RO0Agent.config.includeInReport(name))  {
			return;
		}
		
		RO0Agent.out("Deserializing " + name + ": " + Thread.currentThread().getStackTrace().toString());
	}
}
