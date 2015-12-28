package com.contrastsecurity.rO0.TestCases;

import com.contrastsecurity.rO0.RO0Agent;

public class Test {
	public void test(String test, boolean result, boolean expected){
		RO0Agent.out((result==expected?"PASS: ":"FAIL: ") + test);
	}

}
