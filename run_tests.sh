#!/bin/bash

echo "moving to ./bin"
pushd bin

echo "recompiling"
javac ../src/main/java/com/contrastsecurity/rO0/*.java ../src/main/java/com/contrastsecurity/rO0/TestCases/*.java ../src/main/java/com/akamai/security/*.java -classpath ../lib/asm-5.0.4.jar:../lib/asm-commons-5.0.4.jar  -d .

echo "creating jar files"
jar cfm contrast-test.jar ../mf/test.mf    com/contrastsecurity/rO0/TestCases/*.class
jar cfm contrast-ro0.jar  ../mf/contrast.mf com/contrastsecurity/rO0/*.class
jar cfm contrast-ro0-spotfix.jar ../mf/safeois.mf com/akamai/security/*.class

echo "executing tests"
export JARDIR=`pwd`
java -javaagent:${JARDIR}/contrast-ro0.jar -Xbootclasspath/p:"${JARDIR}/contrast-rO0.jar:${JARDIR}/asm-5.0.4.jar:${JARDIR}/asm-commons-5.0.4.jar" -jar contrast-test.jar -Dfile.encoding=UTF-8 -classpath ${JARDIR}/asm-5.0.4.jar:${JARDIR}/asm-commons-5.0.4.jar

java com/akamai/security/TestSafeObjectInputStream

# clean up 
popd
