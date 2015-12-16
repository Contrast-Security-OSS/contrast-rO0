echo "moving to ./bin"
pushd bin

echo "recompiling"
javac ../src/main/java/com/contrastsecurity/rO0/*.java ../src/main/java/com/contrastsecurity/rO0/TestCases/*.java ../src/main/java/com/akamai/security/*.java -classpath ../lib/asm-5.0.4.jar:../lib/asm-commons-5.0.4.jar  -d .

echo "creating jar files"
jar cfm contrast-test.jar ../mf/test.mf    com/contrastsecurity/rO0/TestCases/*.class
jar cfm contrast-ro0.jar  ../mf/contrast.mf com/contrastsecurity/rO0/*.class
jar cfm contrast-ro0-spotfix.jar ../mf/safeois.mf com/akamai/security/*.class

echo "executing tests"
java -javaagent:/Users/akatz/git/rO0/contrast-ro0/bin/contrast-ro0.jar -Xbootclasspath/p:"/Users/akatz/git/rO0/contrast-ro0/bin/contrast-rO0.jar:/Users/akatz/git/rO0/contrast-ro0/lib/asm-5.0.4.jar:/Users/akatz/git/rO0/contrast-ro0/lib/asm-commons-5.0.4.jar" -jar contrast-test.jar -Dfile.encoding=UTF-8 -classpath /Users/akatz/git/rO0/contrast-ro0/bin:/Users/akatz/git/rO0/contrast-ro0/lib/asm-5.0.4.jar:/Users/akatz/git/rO0/contrast-ro0/lib/asm-commons-5.0.4.jar

java -jar contrast-ro0-spotfix.jar -classpath:contrast-ro0.jar

# clean up 
popd
