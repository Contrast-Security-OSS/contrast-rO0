package com.contrastsecurity.rO0.TestCases;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.util.Arrays;

import com.contrastsecurity.rO0.RO0Agent;
import com.contrastsecurity.rO0.TestCases.BlacklistElement;
import com.contrastsecurity.rO0.TestCases.UnlistedElement;
import com.contrastsecurity.rO0.TestCases.WhitelistElement;

public class TestResolveClassController 
	extends Test
{

	public void run() {
		RO0Agent.out("--------------------------------------------------");
		RO0Agent.out("----- Beginning ResolveClassController tests -----");

		RO0Agent.out("----- trying to load java agent -----");
		
		BlacklistElement blacklistElement = new BlacklistElement();
		WhitelistElement whitelistElement = new WhitelistElement();
		UnlistedElement  unlistedElement = new UnlistedElement();
		
		test("verifying flag to load rO0 has been set",
			RO0Agent.loaded,
			true);
		
		test("verifying whitelisting is disabled",
			 RO0Agent.config.getWhitelistEnabled(),
			 false);
		test("verifying blacklisting is disabled",
			 RO0Agent.config.getBlacklistEnabled(),
			 false);
		test("verifying reporting is disabled by default",
			 RO0Agent.config.getReportingEnabled(),
			 false);
		RO0Agent.config.setReporting(false);
		test("verifying reporting is now disabled",
			 RO0Agent.config.getReportingEnabled(),
			 false);
		test("verifying class ignore is disabled",
			 RO0Agent.config.getClassIgnoreEnalbed(),
			 false);
		test("verifying stack ignore is disabled",
			 RO0Agent.config.getStackIgnoreEnabled(),
			 false);			 
				
		RO0Agent.out("----- If no lists are loaded.  Everything should deserailize. -----");

		test("verifying whitelisted object serializes",
			 tryToSerialize(whitelistElement),
			 true);
		
		test("verifying blacklisted object serializes",
			 tryToSerialize(blacklistElement),
			 true);
		test("verifying unlisted object serializes",
			 tryToSerialize(unlistedElement),
			 true);
	

		RO0Agent.out("----- Load all lists, but don't enable any of them -----");
		try {
			RO0Agent.config.readConfig("../config/unit_test_config_1");
			RO0Agent.config.readConfig("../config/unit_test_config_2");
			RO0Agent.config.readConfig("../config/unit_test_config_3");
		} catch (FileNotFoundException e) {
			RO0Agent.out("FAIL: unable to load config files");
			e.printStackTrace();
		}
		test("verifying whitelisted object serializes",
			 tryToSerialize(whitelistElement),
			 true);
		test("verifying blacklisted object serializes",
			 tryToSerialize(blacklistElement),
			 true);
		test("verifying unlisted object serializes",
			 tryToSerialize(unlistedElement),
			 true);

		RO0Agent.out("----- Enable whitelisting -----");
		RO0Agent.config.setWhitelisting(true);
		test("verifying whitelisted object serializes",
			 tryToSerialize(whitelistElement),
			 true);
		test("verifying blacklisted object doesn't serialize",
			 tryToSerialize(blacklistElement),
			 false);
		test("verifying unlisted object doesn't serialize",
			 tryToSerialize(unlistedElement),
			 false);
		
		RO0Agent.out("----- Disable whitelisting and enable blacklisting -----");
		RO0Agent.config.setWhitelisting(false);
		RO0Agent.config.setBlacklisting(true);
		test("verifying whitelisted object serializes",
			 tryToSerialize(whitelistElement),
			 true);
		test("verifying blacklisted object doesn't serialize",
			 tryToSerialize(blacklistElement),
			 false);
		test("verifying unlisted object serializes",
			 tryToSerialize(unlistedElement),
			 true);
		
		// Reporting can't easily be tested without replacing RO0Agent.out... that doesn't seem 
		// necessary but unit tests could be added if deemed required.  There is related coverage
		// in TestRO0Config, to at least ensure that configuration for reporting
		// is correctly implemented.
	}
	
	private boolean tryToSerialize(Serializable object)
	{
		try {
			byte[] bytes = serialize(object);
			Serializable object2 = deserialize(bytes);
			
			// validate match
			byte[] bytes2 = serialize(object2);
			if(Arrays.equals(bytes,  bytes2)) return true;
		} catch ( SecurityException se ) { 
			return false;
		} catch ( IOException ioe ) {
			throw new RuntimeException(ioe);
		} catch (ClassNotFoundException cnfe) {
			throw new RuntimeException(cnfe);
		}
		return false;
	}
	
	private byte[] serialize(Serializable object) throws IOException
	{
		ByteArrayOutputStream bytes = new ByteArrayOutputStream(); 
		ObjectOutputStream out = new ObjectOutputStream(bytes);
		out.writeObject(object);
		return bytes.toByteArray();
	}
	
	private Serializable deserialize(byte[] bytes) throws IOException, ClassNotFoundException {
		ObjectInputStream in = new ObjectInputStream(new ByteArrayInputStream(bytes));
		return (Serializable)in.readObject();
	}
	
}
