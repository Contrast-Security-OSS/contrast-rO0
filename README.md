contrast-rO0
========

A lightweight Java agent for preventing attacks against object deserialization
like those discussed by [@breenmachine](http://foxglovesecurity.com/2015/11/06/what-do-weblogic-websphere-jboss-jenkins-opennms-and-your-application-have-in-common-this-vulnerability/#websphere)
and the original researchers [@frohoff and @gebl](http://www.slideshare.net/frohoff1/appseccali-2015-marshalling-pickles), affecting WebLogic, JBoss, Jenkins and
more.

## Why did you make this?
This is the only way to hotpatch your application against this vulnerability. 
Patching the code is possible (and this package contains SafeObjectInputStream to help), 
but for many applications, patches will not be available for a long time. Because of 
the nature of the vulnerability, some applications will have to re-architect their 
messaging completely.

## How do I use the library?


### JVM-wide fix

Build the agent, first:
```
git clone https://github.com/Contrast-Security-OSS/contrast-rO0.git
cd contrast-rO0
mvn clean package test
```
The agent, contrast-rO0.jar, is now in the /target directory. Now you need to copy the contrast-rO0.jar into your classpath, and copy the configuration file somewhere you'll remember.

The final step is to add the following JVM options to your server or application:
```
-javaagent:/path/to/contrast-rO0.jar -DrO0.reporting=false -DrO0.blacklist=true -DrOo.lists=filename
```
where 'filename' is the path to the default config file.

Now you're safe serializing from known dangerous classes!


### Spot Fix

If you'd prefer to spot fix your code, possibly because you need to use dangerous classes somewhere, or because you need to minimize stability risk, you can use the SafeObjectInputStream class.  To use this class, you'll need to replace calls to ObjectInputStream in your code with calls to SafeObjectInputStream.  

When you use SafeObjectInputStream, you can either whitelist or blacklist classes - whitelisting is safer, but blacklisting has lower stability risk.  If you want to use this, you don't need the java command line options listed above.  Instead, construct your SafeObejctInputStream, tell it if you want to blacklist or whitelist, and add the whitelisted/blacklisted classes to the stream.  NOTE: you'll have to repeat this everywhere in your code where you need to implement safe deserialization.

```
SafeObjectInputStream in 
   = new SafeObjectInputStream(inputStream, true);  // whitelisting mode
// or 
// = new SafeObjectInputStream(inputStream, false); // blacklisting mode
in.addToWhitelist(ClassThatIsSafeToDeserialize.getName());
in.addToWhitelist("com.my.SafeDeserializable");
// or
// in.addToBlacklist(ClassThatIsDangerous.class);

// then just use like normal
in.readObject();
```

### Reporting on Serialization Usage
The shim can be instructed to report when serialization occurs.  This allows you to determine where in your application deserialization is actually occurring - assuming that you exercise the relevant functionality.

To use this, built it just as described in "JVM-wide fix" but, use the following command line options instead:

```
-javaagent:/path/to/contrast-rO0.jar
```

## What does it do?
When protecting your application, the JVM-wide shim or the SafeObjectInputStream spot fix will throw a SecurityException if there is an attempt to deserialize a dangerous object.

This represents the "last mile" of the exploit chain. The default blacklist contains the only publicly known proofs-of-concept, which are extremely unlikely to be used for legitimate purposes during deserialization. 

* org.apache.commons.collections.functors.InvokerTransformer
* org.apache.commons.collections4.functors.InvokerTransformer
* org.apache.commons.collections.functors.InstantiateTransformer
* org.apache.commons.collections4.functors.InstantiateTransformer
* org.codehaus.groovy.runtime.ConvertedClosure
* org.codehaus.groovy.runtime.MethodClosure
* org.springframework.beans.factory.ObjectFactory

Though there likely exist other exploitable classes, they are difficult to find, and likely won't be part of any mass exploitation tool for a while.

However, when they do become available, you can update your configuration file to include these classes in your blacklist.  Or, if you want to be more secure, you can use this tool in "reporting" mode to learn what you're deserializing, and then specify a whitelist of the classes that you want to allow.  If you go with this approach, and you don't happen to include a dangerous class in your whitelist, then new research finding additional dangerous classes won't affect you.

## What's the synopsis of all configuration options and usage modes?

```
-DrO0.reporting=true       Enable reporting ().  Reporting is enabled by 
                           default.  Intended for use if we ever use this 
                           package for protecting instead of just reporting.
-DrOo.lists=filename       Specify a configuration file.  File specifies 
                           classes to include in the whitelist, blacklist, 
                           ignore classes list, or ignore stack trace list.
      FIRST        MEANING 
        CHAR
        +          If the line starts with +, it’s included in the whitelist.
                   Attempts to deserialize any classes not whitelisted will 
                   throw a SecurityException.  Only has effect when 
                   -DrO0.whitelist is enabled.

        -          If the line starts with -, it’s included in the blacklist.  
                   Attempts to deserialize these classes will throw a 
                   SecurityException.  Only has effect when -DrO0.blacklist is
                   enabled.

        $          If the line starts with $, it’s included in the “ignore 
                   class list”.  Classes in this list will not be reported.
                   Only has effect when -DrO0.ignoreClasses is enabled

        @          If the line starts with @, it’s included in the “ignore 
                   in stack list”.  When a class is deserialized and the class 
                   specified by this line is in the stack, don’t report.  Only 
                   has effect when -DrO0.ignoreStack is enabled.

-DrO0.whitelist=true       Enable whitelisting.  Classes not included in the 
                           config file as whitelisted will not be allowed to 
                           deserialize.  You can enable this at the same time as
                           blacklisting.  See the section on "enabling both 
                           blacklisting and whitelisting at the same time" for
                           details.

-DrO0.blacklist=true       Enable blacklisting.  Classes included in the config 
                           file as blacklisted will not be allowed to 
                           deserialized; all other classes will deserialize 
                           normally.   You can enable this at the same time as
                           blacklisting.  See the section on "enabling both 
                           blacklisting and whitelisting at the same time" for
                           details.

-DrO0.ignoreClasses=true   Used to quiet down the tool when it’s doing 
                           reporting.  Classes or packages listed as ignored 
                           will not be reported upon.  Only useful if reporting 
                           is enabled.  Can be used in combination with 
                           -DrO0.ignoreStack.

-DrO0.ignoreStack=true     Used to quiet down the tool when it’s doing 
                           reporting.  If the specified class  or package is 
                           in the stack during deserialization, that 
                           deserialize attempt will not be reported upon.  
                           For example, used to stop logging all memcached 
                           events if @com.danga.Memcached is included in the 
                           config file and ignoreStack is enabled., memcached 
                           should be much less pronounced in the logs.  Likely 
                           to have noticeable performance impact.  Can be 
                           specified in combination with -DrO0.gnoreClasses.  
                           Only useful if reporting is enabled.
                           
-DrO0.outfile=filename     Used to control where output from this utility is sent.
                           If no output is specified, it will go to System.out.  If
                           filename is specified, rO0 will try to write
                           output to the specified location; if it cannot (for example
                           if permissions disallow this) then rO0 will instead
                           fall back to System.out. 
```

### Enabling both blacklisting and whitelisting at the same time
This tool allows you to enable both blacklisting and whitelisting at the same time.  
If you do so, a class will only be allowed to deserialize if it's *both* on the 
whitelist and not on the blacklist.  This is useful if you want to maintain a list
of known dangerous classes that you never want to deserialize as backup in case 
someone accidentally or unknowingly adds that same class to the white list.

## Supported systems
Although it's not tested on them all, the agent should work well on the following platforms:
* Java 5-8
* OpenJDK/HotSpot, JRockit, IBM

## Who made this?
This project is sponsored by [Contrast Security](http://www.contrastsecurity.com/) and released under the BSD license for developers.  It includes contributions from Akamai Technologies.

![Contrast Security Logo](http://cdn2.hubspot.net/hub/203759/file-2275798868-png/theme/Contrast-logo-transparent.png "Contrast Logo")
