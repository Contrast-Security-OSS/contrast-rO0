package com.contrastsecurity.rO0.TestCases;

import java.io.FileNotFoundException;

import com.contrastsecurity.rO0.RO0Config;
import com.contrastsecurity.rO0.RO0Agent;
import com.contrastsecurity.rO0.TestCases.BlacklistElement;
import com.contrastsecurity.rO0.TestCases.IgnoreClassListElement;
import com.contrastsecurity.rO0.TestCases.UnlistedElement;
import com.contrastsecurity.rO0.TestCases.WhitelistElement;

public class TestRO0Config 
extends Test
{

	public void run() {
		RO0Agent.out("----- Beginning DeserialFoilConfig tests -----");
		RO0Config config = new RO0Config();

		RO0Agent.out("----- Testing All-Disabled Config -----");
		config.setBlacklisting(false);;
		config.setReporting(false);
		config.setWhitelisting(false);
		config.setBlacklisting(true);
		test("check disabled blacklist disallows nothing",
				config.isBlacklisted(Object.class),
				false);
		test("check disabled whitelist allows everything",
				config.isWhitelisted(Object.class),
				true);
		test("check disabled report filters filter everything",
				config.includeInReport(Object.class),
				false);


		RO0Agent.out("----- Testing Empty Config, each enabled in turn -----");
		config.setBlacklisting(true);
		test("check empty, enabled blacklist disallows nothing",
				config.isBlacklisted(Object.class),
				false);
		config.setWhitelisting(true);
		test("check empty, enabled whitelist allows nothing",
				config.isWhitelisted(Object.class),
				false);
		config.setReporting(true);
		test("check empty, enalbed report still filters filter nothing",
				config.includeInReport(Object.class),
				true);


		RO0Agent.out("----- Test 1 blacklisted element -----");
		config.setBlacklisting(true);
		config.setWhitelisting(false);;
		config.addToBlacklist(Object.class);
		test("check blacklisted element is found on blacklist",
				config.isBlacklisted(Object.class),
				true);
		test("check NON-blacklisted element is not found on blacklist",
				config.isBlacklisted(Integer.class),
				false);
		test("check whitelist pretends everything is whitelisted when blacklist is enabled",
				config.isWhitelisted(Object.class),
				true);
		test("check reporting is unaffected by enabling blacklisting - still nothing is filtered",
				config.includeInReport(Object.class),
				true);

		RO0Agent.out("----- Test 1 whitelisted element -----");
		config.setWhitelisting(true);
		config.setBlacklisting(false);
		config.addToWhitelist(Object.class);
		test("check blacklisting is disabled (pretends blacklisted element isn't blacklisted)",
				config.isBlacklisted(Object.class),
				false);
		test("check NON-blacklisted element is still not on the blacklist",
				config.isBlacklisted(Integer.class),
				false);
		test("check whitelisted element is on the whitelist",
				config.isWhitelisted(Object.class),
				true);
		test("check non-whitelisted element is not on the white list",
				config.isWhitelisted(Integer.class),
				false);
		test("check reporting hasn't changed",
				config.includeInReport(Object.class),
				true);

		RO0Agent.out("----- Test that reporting class filters correctly work");
		config.addToClassIgnoreList(Object.class);
		config.setReporting(true);
		config.setWhitelisting(false);
		test("check blacklisting continues to pretend the list is empty when reporting is enabled",
				config.isBlacklisted(Object.class),
				false);
		test("check NON-blacklisted element still isn't found on the blacklist, either",
				config.isBlacklisted(Integer.class),
				false);
		test("check whitelisted still allows the previously whitelisted object...",
				config.isWhitelisted(Object.class),
				true);
		test("and that whitelisting is disabled and therefore pretends everything is whitelisted when reporting enabled",
				config.isWhitelisted(Integer.class),
				true);
		test("check reporting wants to include a non-filtered class in the report",
				config.includeInReport(Integer.class),
				true);
		test("check reporting wants filtered classes in the report when class filtering is disabled",
				config.includeInReport(Object.class),
				true);		
		test("check reporting wants unfiltered classes in the report when class filtering is enabled",
				config.includeInReport(Integer.class),
				true);
		config.setClassFiltering(true);
		test("check reporting doesn't want filtered classes in the report when class filtering is enabled",
				config.includeInReport(Object.class),
				false);
		test("check reporting still wants unfiltered classes in the report when class filtering is enabled",
				config.includeInReport(Integer.class),
				true);
		config.addToStackIgnoreList(getClass().getName());
		test("check reporting wants configured-but-disaled stack-filtered stuff in the report when stack-filtering is disabled",
				config.includeInReport(Integer.class),
				true);
		test("check that the configred-but-disabled stack ignore list has no effect when stack ignore is disabled - unfiltered class is still reported",
				config.includeInReport(Integer.class),
				true);
		config.setClassFiltering(false);;
		test("check that cofigred-but-disabled stack filtering still has no effect if class filtering is disabled.  filtered class is reported",
				config.includeInReport(Object.class),
				true);
		test("Check that configured-but-disabled stack filtering also allows non-filtered class);",
				config.includeInReport(Integer.class),
				true);
		config.setStackFiltering(true);
		test("Check that enabled stack filtering is allowed when on the stack",
				config.includeInReport(Integer.class),
				false);
		
		RO0Agent.out("----- Test proper loading of config file -----");
		config = new RO0Config();
		try {
			config.readConfig("../config/unit_test_config_1");
			config.readConfig("../config/unit_test_config_2");
		} catch (FileNotFoundException e) {
			RO0Agent.out("FAIL: Unable to load config file 1");
			RO0Agent.out(e);
		}
		config.setBlacklisting(true);
		config.setWhitelisting(true);
		config.setReporting(true);
		config.setClassFiltering(true);;
		test("Test class ignore list includes class ignore element",
			 config.includeInReport(IgnoreClassListElement.class),
			 false);
		test("Test class ignore list does not include unlisted element",
			 config.includeInReport(UnlistedElement.class),
			 true);
		test("Test class ignore list does not include whitelist element",
			 config.includeInReport(WhitelistElement.class),
			 true);
		test("Test class ignore list does not include blacklist element",
		     config.includeInReport(BlacklistElement.class),
		     true);
		
		// testing stack ignore requires a separate config file, to put this class
		// in the ignore stack, so this piece had to be set up after the above
		// class-ignore tests
		try {
			config.readConfig("../config/unit_test_config_3");
		} catch (FileNotFoundException e) {
			RO0Agent.out("FAIL: Unable to load config file 1");
			RO0Agent.out(e);
		}
		test("Test stack ignore list affects class ignore element",
			 config.includeInReport(IgnoreClassListElement.class),
			 false);
		test("Test reporting includes unlisted element",
			 config.includeInReport(UnlistedElement.class),
			 true);
		test("Test reporting includes whitelisted element",
			 config.includeInReport(WhitelistElement.class),
			 true);
		test("Test reporting includes blacklisted element",
		     config.includeInReport(BlacklistElement.class),
		     true);
		

		test("test blacklist includes blacklisted element",
			 config.isBlacklisted(BlacklistElement.class),
			 true);
		test("Test blacklist does not include unlisted element",
			 config.isBlacklisted(UnlistedElement.class),
			 false);
		test("Test blacklist does not include whitelisted element",
			 config.isBlacklisted(WhitelistElement.class),
			 false);
		test("Test blacklist does not include report ignore element",
			 config.isBlacklisted(IgnoreClassListElement.class),
			 false);
		test("Test blacklist does not include stack ignore element",
			 config.isBlacklisted(TestResolveClassController.class),
			 false);
		
		test("Test whitelist includes whitelisted element",
			 config.isWhitelisted(WhitelistElement.class),
			 true);
		test("test whitelist does not include unlisted element",
			 config.isWhitelisted(UnlistedElement.class),
			 false);
		test("test whitelist does not include blacklisted element",
			 config.isWhitelisted(BlacklistElement.class),
			 false);
		test("Test whitelist does not include class-ignore element",
			 config.isWhitelisted(IgnoreClassListElement.class),
			 false);
		test("Test whitelist does not include stack ignore element",
			 config.isWhitelisted(TestResolveClassController.class),
			 false);
	}
}
