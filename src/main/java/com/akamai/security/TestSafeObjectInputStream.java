package com.akamai.security;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.util.Arrays;
import java.util.Hashtable;

import com.contrastsecurity.rO0.DeserialFoilConfig;

public class TestSafeObjectInputStream implements Serializable {

	public static void main(String[] args) {
		TestSafeObjectInputStream test = new TestSafeObjectInputStream();
		test.run();
	}
	
	private static final boolean EXPECT_EXCEPTION = true;
	private static final boolean SHOULD_NOT_EXCEPT = false;
	
	public void run() {
	}			
}
