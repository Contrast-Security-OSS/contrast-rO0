package com.akamai.security;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.util.Arrays;

import com.contrastsecurity.rO0.TestCases.Test;
import com.contrastsecurity.rO0.TestCases.BlacklistElement;
import com.contrastsecurity.rO0.TestCases.UnlistedElement;
import com.contrastsecurity.rO0.TestCases.WhitelistElement;

public class TestSafeObjectInputStream
	extends Test
{
	public static void main(String[] args)
	{
		TestSafeObjectInputStream test = new TestSafeObjectInputStream();
		try {
			test.run();
		} catch (Throwable t) {
			out("FAIL! FAIL! FAIL: Unexpected exception");
			out(t);
		}
	}

	public void run() throws IOException {
		out("--------------------------------------------------");
		out("----- Beginning SafeObjectInputStream tests -----");

		testWhitelist();
		testBlacklist();
	}

	private void testWhitelist() throws IOException
	{
		out("----- Test in whitelisting mode -----");
		WhitelistElement whitelistElement = new WhitelistElement();
		BlacklistElement blacklistElement = new BlacklistElement();
		UnlistedElement  unlistedElement  = new UnlistedElement();

		byte[] w = serialize(whitelistElement);
		byte[] b = serialize(blacklistElement);
		byte[] u = serialize(unlistedElement);
		
		ByteArrayInputStream bin_w = new ByteArrayInputStream(w);
		ByteArrayInputStream bin_b = new ByteArrayInputStream(b);
		ByteArrayInputStream bin_u = new ByteArrayInputStream(u);
		
		SafeObjectInputStream in_w = new SafeObjectInputStream(bin_w, true);
		SafeObjectInputStream in_b = new SafeObjectInputStream(bin_b, true);
		SafeObjectInputStream in_u = new SafeObjectInputStream(bin_u, true);
		
	    in_w.addToWhitelist(WhitelistElement.class);
		in_b.addToWhitelist(WhitelistElement.class);
		in_u.addToWhitelist(WhitelistElement.class);

		test("verifying whitelisted object deserializes with whitelist",
			 tryToDeserialize(w, in_w),
			 true);
		test("verifying blacklisted object doesn't deserialize with whitelist",
			 tryToDeserialize(b, in_b),
			 false);
		test("verifying unlisted object doesn't deserialize with whitelist",
			 tryToDeserialize(u, in_u),
			 false);
	}

	private void testBlacklist() throws IOException
	{
		out("----- Test in blacklisting mode -----");
		WhitelistElement whitelistElement = new WhitelistElement();
		BlacklistElement blacklistElement = new BlacklistElement();
		UnlistedElement  unlistedElement  = new UnlistedElement();

		byte[] w = serialize(whitelistElement);
		byte[] b = serialize(blacklistElement);
		byte[] u = serialize(unlistedElement);
		
		ByteArrayInputStream bin_w = new ByteArrayInputStream(w);
		ByteArrayInputStream bin_b = new ByteArrayInputStream(b);
		ByteArrayInputStream bin_u = new ByteArrayInputStream(u);
		
		SafeObjectInputStream in_w = new SafeObjectInputStream(bin_w, false);
		SafeObjectInputStream in_b = new SafeObjectInputStream(bin_b, false);
		SafeObjectInputStream in_u = new SafeObjectInputStream(bin_u, false);
		
	    in_w.addToBlacklist(BlacklistElement.class);
		in_b.addToBlacklist(BlacklistElement.class);
		in_u.addToBlacklist(BlacklistElement.class);

		test("verifying whitelisted object deserializes with blacklist",
			 tryToDeserialize(w, in_w),
			 true);
		test("verifying blacklisted object doesn't deserialize with blacklist",
			 tryToDeserialize(b, in_b),
			 false);
		test("verifying unlisted object doesn't deserializes with blacklist",
			 tryToDeserialize(u, in_u),
			 true);
	}
		
	
	private boolean tryToDeserialize(byte[] orig_bytes, SafeObjectInputStream in)
	{
		try {
			// this first line will throw an exception if deserialization is 
			// not allowed
			Serializable object = (Serializable)in.readObject();
			
			// these lines ensure that the object really deserialized correctly
			// and our test is valid.
			byte[] new_bytes = serialize(object);
			if(Arrays.equals(orig_bytes, new_bytes)) return true;
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
	
	private static void out(String s)
	{
		System.out.println(s);
		System.out.flush();
	}

	private static void out(Throwable t)
	{
		t.printStackTrace();
	}
	
}
