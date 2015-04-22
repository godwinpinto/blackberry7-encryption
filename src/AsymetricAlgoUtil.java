import java.io.ByteArrayOutputStream;

import net.rim.device.api.crypto.BlockEncryptor;
import net.rim.device.api.crypto.PKCS1FormatterEngine;
import net.rim.device.api.crypto.RSACryptoSystem;
import net.rim.device.api.crypto.RSAEncryptorEngine;
import net.rim.device.api.crypto.RSAPublicKey;
import net.rim.device.api.crypto.encoder.PublicKeyDecoder;
import net.rim.device.api.io.Base64InputStream;
import net.rim.device.api.io.Base64OutputStream;

import com.phyder.fwk.exhandler.CustomLogger;

public class AsymetricAlgoUtil {

	public static String encryptData(String strPlainText) {
		try {
			byte[] messageBytes = strPlainText.getBytes();
			String strPublicKey = "YOUR_PUBLIC_KEY";
			RSACryptoSystem rsa = new RSACryptoSystem(2048);
			RSAPublicKey rsakey = (RSAPublicKey) PublicKeyDecoder.decode(Base64InputStream.decode(strPublicKey), "X509");
			RSAEncryptorEngine rsaEncryption = new RSAEncryptorEngine(rsakey);
			PKCS1FormatterEngine padder = new PKCS1FormatterEngine(rsaEncryption);
			ByteArrayOutputStream output = new ByteArrayOutputStream();
			BlockEncryptor encryptor = new BlockEncryptor(padder, output);
			encryptor.write(messageBytes);
			encryptor.close();
			output.flush();
			byte[] ciphertextBytes = output.toByteArray();
			return Base64OutputStream.encodeAsString(ciphertextBytes, 0, ciphertextBytes.length, false, false);
		} catch (Throwable t) {
			t.printStackTrace();
		}
		return null;
	}
}