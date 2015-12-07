package com.akamai.security;

import com.contrastsecurity.rO0.DeserialFoilConfig;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectStreamClass;
import java.util.Hashtable;

public class SafeObjectInputStream extends ObjectInputStream {

	DeserialFoilConfig config = new DeserialFoilConfig();
	
	Hashtable<String,String> classList = new Hashtable<String,String>();

	/* true = white list; false = blacklist */
	public static final boolean WHITELIST = true;
	public static final boolean BLACKLIST = false;
	
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

	public void addToWhitelist(Class<?> klass) {
		config.addToWhitelist(klass);
	}
	
	public void addToBlacklist(Class<?> klass) {
		config.addToBlacklist(klass);
	}
		
	public DeserialFoilConfig getConfig() { return config; }
	
	public void setConfig(DeserialFoilConfig config){ this.config = config; }
	
	protected Class<?> resolveClass(ObjectStreamClass desc) 
		throws IOException, ClassNotFoundException
	{
		String name = desc.getName();
		if( config.isBlacklisted(name) ) {
			String message = "Attempt to deserialize blacklisted class:" + name;
			throw new SecurityException(message); 
		} 
		
		if( config.isWhitelisted(name) ) {
			String message = "Attempt to deserialize non-whitelisted class: " + name;
			throw new SecurityException(message);
		}
		
		return super.resolveClass(desc);
	}
}
