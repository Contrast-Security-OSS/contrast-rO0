package com.contrastsecurity.rO0;

import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.util.Vector;

public class RO0Config {

	/** Flag indicating if reporting is enalbed or disabled.  Enabled by default.  **/
	private boolean reportingEnabled = true;
	
	/**
	 * Flag indicating whether we're supposed to ignore any classes during reporting.
	 * Enabled if the config file specified ignore classes.
	 */
	private boolean classIgnoreEnabled = false;
	
	/**
	 * List of classes to ignore during reporting.  That is, don't report if there are 
	 * deserialization attempts for these classes.  This is to reduce the noise in the log
	 * file for known safe stuff.
	 */
	private Vector<String> classIgnoreList = new Vector<String>();
	
	
	/**
	 * Flag indicating that we should ignore deserialization attempts for classes with any of
	 * the listed superclasses in their stack.  This is intended to allow us to ignroe things like
	 * serialization via memcache.  This can be helpful when trying to figure out whwere in the 
	 * application deserialization occurs, as it allows us to ignore the stuff we know about and
	 * keep the output log limited to the stuff we want to investigate. 
	 */
	private boolean stackIgnoreEnabled = false;
	
	/**
	 * List of classes that, if found on the stack while in reporting mode, should result in NOT logging
	 * the deserialization attempt.
	 */
	private Vector<String> stackIgnoreList = new Vector<String>();
		
	/**
	 * Flag to indicate if we're in whitelisting mode.  Deserailziation of expected classes will be 
	 * allowed.  Deserialization of non-whitelisted classes will result in a SecurityException.
	 * Note that whitelisting is prone to usability/funcitonal failure if it's incomplete.  If you
	 * don't whitelist a class you need, you will not have access to that functionality.
	 */
	private boolean whitelistEnabled = false;
	
	/**
	 * If we're in whitelisting mode, this array will contain all whitelisted classes.  Deserialization
	 * of these classes will be allowed; deserialization of anything unlisted willr esult in a SecurityException
	 */
	private Vector<String> whitelist = new Vector<String>();
	
	/** 
	 * Flag to indicate if blacklisting is enabled.  If it is, deserialization attempts on listed classes
	 * will result in a SecurityException; deserialization attempts on unlisted classes will be allowed.  
	 * Note that blacklisting is inherently prone to security failure - if you fail to blacklist a class
	 * that is dangerous, you'll have a vulnerability.
	 */
	private boolean blacklistEnabled = false;
	
	/**
	 * List of classes that are blacklisted.  If blacklisting is enalbed, attempts to load these
	 * classes will result in a SecurityException.
	 */
	private Vector<String> blacklist = new Vector<String>();

	/**
	 * Read the specified file and parse the configuration.
	 * @param filename
	 * @throws FileNotFoundException 
	 */
	public void readConfig(String filename) throws FileNotFoundException {
		if( filename == null || filename.equals("") ) return;
		readConfig(new FileReader(filename));
	}
	
	/**
	 * See readConfig(String)
	 * 
	 * @param file
	 */
	public void readConfig(FileReader file) {
		if(file == null) return;
		
		BufferedReader in = null;
		try {
			in = new BufferedReader(file);
			
			String line = null;
			do {
				line = in.readLine();
				if( line == null ) continue;
				line = line.trim();
				
				if(line.startsWith("#")) continue; // # is comment character if 1st char in line
				if(line.startsWith("-")) addToBlacklist(line.substring(1,line.length()).trim());
				if(line.startsWith("+")) addToWhitelist(line.substring(1,line.length()).trim());
				if(line.startsWith("$")) addToClassIgnoreList(line.substring(1,line.length()).trim());
				if(line.startsWith("@")) addToStackIgnoreList(line.substring(1,line.length()).trim());
			} while(line != null );			
		} catch (FileNotFoundException fnfe) {
			RO0Agent.out("Unable to set up ignore list");
			fnfe.printStackTrace();
		} catch (IOException ioe) {
			RO0Agent.out("Error reading ignorelist config file");
			ioe.printStackTrace();
		} finally {
			try { if( in != null ) { in.close(); } } catch ( Exception e) { /* do nothing*/ }
		}
	}

	/** 
	 * Called during reporting to check if the current class is filtered out of the 
	 * report.  It's safe to call this without first checking if reporting is enabled;
	 * this method returns false if reporting is disabled.
	 * 
	 * @param className
	 * @return true if the event should be included in the output report.  False if it should NOT be 
	 *         included in the report.  "false" can be the case if reporting is disabled, of if the class
	 *         or an element in the current call stack is filtered out via the config file.
	 */
	public boolean includeInReport(String className) {
		if( ! getReportingEnabled() ) 
		{ 
			return false; 
		}
		
		if( this.getClassIgnoreEnabled() && isOnClassIgnoreList(className) )
		{
			return false;
		}
		
		if( getStackIgnoreEnabled() && isOnStackIgnoreList(Thread.currentThread().getStackTrace()))
		{
			return false; 
		}
		
		return true;
	}
	
	public void setStackFiltering(boolean enabled)
	{
		this.stackIgnoreEnabled = enabled;
	}
	
	public void setClassFiltering(boolean enabled)
	{
		this.classIgnoreEnabled = enabled;
	}
	
	/**
	 * Internal helper method to determine if a class name is on the list of classes to ignore.
	 * 
	 * @param name the class name to check
	 * 
	 * @return ture if it's on the list; false if it's not on the list
	 */
	private boolean isOnClassIgnoreList(String name){
		return isOnList(classIgnoreList, name);
	}

	/**
	 * Internal helper method to determine if the specified stack trace contains any element
	 * that is on the list of stack trace elements to ignore.  A match indicates that the 
	 * current stack trace matches something from the configuration file.
	 * 
	 * @param stackTrace the stack trace to check
	 * @return true if there's a match; false if there's no match.
	 */
	private boolean isOnStackIgnoreList(StackTraceElement[] stackTrace) {
		if( getStackIgnoreEnabled() == false ) return false;
		if( stackIgnoreList.isEmpty()   ) return false;
				
		for( int i=0; i<stackTrace.length; i++) {
			if( isOnList(stackIgnoreList, stackTrace[i].getClassName()) ) return true;
		}
		
		return false;
	}

	/**
	 * Determines if a class is blacklisted.  If it's blacklisted, deserialization should not be allowed.
	 * Otherwise, deserialization should be allowed.  This method is safe to call without first checking
	 * if blacklisting is enabled - if blacklisting is disabled, this method will always return "false".
	 * 
	 * @param name the class to see if it's blacklisted.
	 * 
	 * @return true if blacklisted; false if not blacklisted or if blacklisting is disabled.
	 */
	public boolean isBlacklisted(String name) {
		if( getBlacklistEnabled() == false ) { return false; }
		return isOnList(blacklist, name);
	}

	@SuppressWarnings("rawtypes")
	public boolean isBlacklisted(Class klass) {
		return isBlacklisted(klass.getName());
	}
	
	public boolean getWhitelistEnabled() { return this.whitelistEnabled; }
	public boolean getBlacklistEnabled() { return this.blacklistEnabled; }
	public boolean getClassIgnoreEnabled() { return this.classIgnoreEnabled; }
	public boolean getStackIgnoreEnabled() { return this.stackIgnoreEnabled; }
	public boolean getReportingEnabled() { return this.reportingEnabled; }
	
	/**
	 * Determines if a class is whitelisted.  If it's NOT whitelisted, deserialization should not be 
	 * allowed.  Otherwise, deserialization should be allowed.  This method is safe to call if whitelisting
	 * is disabled.  If whitelisting is disabled, this method will always return "true"
	 * 
	 * <p>NOTE: This method DOES NOT check the call stack, just the specific class.  This is because
	 * checking the call stack could have a performance hit in production, which we are not (yet?) willing
	 * to risk.
	 * 
	 * @param name the class to check if it's whitelisted.
	 * @return true if the class is whitelisted or if whitelisting is disabled.  False if whitelisting is
	 *         enabled but the class is not whitelisted.
	 */
	public boolean isWhitelisted(String name) {
		if( getWhitelistEnabled() == false ) return true;
		return isOnList(whitelist, name);
	}
	
	@SuppressWarnings("rawtypes")
	public boolean isWhitelisted(Class klass) {
		return isWhitelisted(klass.getName());
	}


	/** 
	 * Internal helper method for checking if an entry is on either a Vector or a Hashtable.
	 * If it's in the Vector but not the Hashtable, then the Hashtable will be updated to include
	 * the item, so that future lookups are faster.
	 * 
	 * @param list
	 * @param cache
	 * @param name
	 * @return true if the named class is listed either in the vector or the hashtable
	 */
	private boolean isOnList(Vector<String> list, String name) {
		
		if(list.size() == 0 ) return false;
		
		for(int i=0; i<list.size(); i++){
			String listName = (String) list.get(i);
			if( name.endsWith(listName) ) 
			{
				return true;
			}
		}
		return false; 
	}

	/** 
	 * Helper method for reducing repeated code.  Adds the specified line to both the 
	 * specified vector and the specified hashtable.
	 * 
	 * @param list
	 * @param cache
	 * @param line
	 */
	private void addToList(Vector<String> list, String line)
	{
		list.addElement(line);
	}

	/**
	 * Adds the specified line to the list of classes that we should filter out of reporting
	 * results if the deserialization event occurred with the specified class in the current 
	 * call stack.  For example, to help ignore if serialization is happening through memcache. 
	 * @param line
	 */
	public void addToStackIgnoreList(String line) {
		addToList(stackIgnoreList, line);
	}

	/**
	 * Adds the specified class name to the list of classes that we should filter out of reporting
	 * results if it is the class being deserialized.
	 * 
	 * @param className
	 */
	public void addToClassIgnoreList(String className){
		addToList(classIgnoreList, className);
	}
	

	/**
	 * Add the specified class to the whitelist.  If whitelisting is enabled, this class will be 
	 * allowed to deserialize, but non-whitelisted classes won't be allowed to deserialize.
	 * @param line
	 */
	public void addToWhitelist(String line) {
		addToList(whitelist, line);
	}
	
	@SuppressWarnings("rawtypes")
	public void addToWhitelist(Class klass){
		addToWhitelist(klass.getName());
	}

	/**
	 * Add the specified class to the blacklist.  If blacklisting is enabled, this class NOT will be 
	 * allowed to desereialize, but non-listed classes will be allowed to deserialize.
	 * 
	 * @param line
	 */
	public void addToBlacklist(String line) {
		addToList(blacklist, line);
	}
	
	@SuppressWarnings("rawtypes")
	public void addToBlacklist(Class klass) {
		addToBlacklist(klass.getName());
	}

	/**
	 * Turns on or off whitelisting.
	 * 
	 * @param isWhitelist
	 */
	public void setWhitelisting(boolean enabled) {
		this.whitelistEnabled = enabled;
	}
	
	/**
	 * Turns on or off blacklisting.
	 * 
	 * @param isBlacklist
	 */
	public void setBlacklisting(boolean enabled) {
		this.blacklistEnabled = enabled;
	}
	
	/**
	 * Turn reporting on or off. 
	 * 
	 * @param enabled
	 */
	public void setReporting(boolean enabled) {
		this.reportingEnabled = enabled;
	}

	@SuppressWarnings("rawtypes")
	public void addToClassIgnoreList(Class class1) {
		addToClassIgnoreList(class1.getName());
	}

	@SuppressWarnings("rawtypes")
	public boolean includeInReport(Class class1) {
		return this.includeInReport(class1.getName());
	}

}
