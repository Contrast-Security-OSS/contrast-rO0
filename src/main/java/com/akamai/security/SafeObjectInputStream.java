package com.akamai.security;

import com.contrastsecurity.rO0.RO0Config;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectStreamClass;
import java.util.Hashtable;

public class SafeObjectInputStream extends ObjectInputStream {

	RO0Config config = new RO0Config();
	
	Hashtable<String,String> classList = new Hashtable<String,String>();

	/**
	 * Construct a new SafeObjectInputStream, specifying whether it is
	 * in whitelisting mode or blacklisting mode.  If whitelisting,
	 * only classes that are added to the whitelist (via addToWhitelist())
	 * will be allowed to deserialize.  If it's in blacklist mode, only
	 * classes <i>not</i> on the blacklist will be allowed to deserialize.
	 * 
	 * @param isWhitelist true if in whiteslist mode; false if in blacklist
	 *                    mode.
	 */
	public SafeObjectInputStream(boolean isWhitelist) throws IOException {
		super();
		this.config.setWhitelisting(isWhitelist);
		this.config.setBlacklisting(!isWhitelist);
	}

	public SafeObjectInputStream(InputStream in, boolean isWhitelist) throws IOException {
		super(in);
		this.config.setWhitelisting(isWhitelist);
		this.config.setBlacklisting(!isWhitelist);
	}

	/* By calling this function and adding a class to the whitelist,
	 * you are attesting that the class you have whitelisted is
	 * completely safe, in that it and its parent constructors do 
	 * NOTHING other than intiialize the class - no business logic, no
	 * threads or processes are started, and nothing that is automatically
	 * operated upon by other classes.  DTOs that contain no business logic
	 * are generally safe.  Other classes may or may not be safe.  
	 * As a quick hint, don't do System.exec(), reflection, or reserve
	 * large resources during initialization.
	 */
	public void addToWhitelist(Class<?> klass) {
		config.addToWhitelist(klass);
	}
	
	public void addToBlacklist(Class<?> klass) {
		config.addToBlacklist(klass);
	}
		
	public RO0Config getConfig() { return config; }
	
	public void setConfig(RO0Config config){ this.config = config; }
	
	protected Class<?> resolveClass(ObjectStreamClass desc) 
		throws IOException, ClassNotFoundException
	{
		String name = desc.getName();
		
		if( config.isBlacklisted(name) ) {
			String message = "Attempt to deserialize blacklisted class:" + name;
			throw new SecurityException(message); 
		} 
		
		if( ! config.isWhitelisted(name) ) {
			String message = "Attempt to deserialize non-whitelisted class: " + name;
			throw new SecurityException(message);
		}
		
		return super.resolveClass(desc);
	}
}
