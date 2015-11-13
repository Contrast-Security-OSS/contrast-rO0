package com.contrastsecurity.rO0;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.util.BitSet;

import org.apache.commons.collections.functors.InvokerTransformer;

import junit.framework.TestCase;

public class DeserializationTest extends TestCase {
	
	public void testDeserialization_Safe() throws Exception {
		BitSet bitset = new BitSet();
		bitset.set(1,2);
		File serializedFile = serialize(bitset);
		BitSet bitset2 = (BitSet) deserialize(serializedFile);
		assertEquals(bitset,bitset2);
	}
	
	public void testDeserialization_Unsafe() throws Exception {
		InvokerTransformer transformer = new InvokerTransformer("foo", new Class[]{}, new Object[]{});
		File serializedFile = serialize(transformer);
		try {
			// try deserialized the file we just wrote -- should break!
			transformer = (InvokerTransformer) deserialize(serializedFile);
			fail("should have failed to deserialize!");
		} catch (SecurityException e) {
			// expected
		} catch (Throwable t) {
			t.printStackTrace();
			fail("Shouldn't have failed for non-security reasons");
		}
	}
	
	private File serialize(Serializable serializable) throws IOException {
		File tmpFile = File.createTempFile("contrast-test", ".ser");
		FileOutputStream fos = new FileOutputStream(tmpFile);
		ObjectOutputStream oos = new ObjectOutputStream(fos);
		oos.writeObject(serializable);
		oos.close();
		fos.close();
		return tmpFile;
	}

	private Object deserialize(File serializable) throws Exception {
		FileInputStream fis = new FileInputStream(serializable);
		ObjectInputStream ois = new ObjectInputStream(fis);
		Object object = ois.readObject();
		ois.close();
		fis.close();
		return object;
	}
}
