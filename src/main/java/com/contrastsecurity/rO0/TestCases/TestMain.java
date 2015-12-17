package com.contrastsecurity.rO0.TestCases;

public class TestMain {

	public static void main(String[] args) {
		TestRO0Config     test1 = new TestRO0Config();
		TestResolveClassController test2 = new TestResolveClassController();
		
		test1.run();
		test2.run();
	}

}
