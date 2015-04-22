
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;

import net.rim.device.api.crypto.AESCBCDecryptorEngine;
import net.rim.device.api.crypto.AESCBCEncryptorEngine;
import net.rim.device.api.crypto.AESEncryptorEngine;
import net.rim.device.api.crypto.AESKey;
import net.rim.device.api.crypto.BlockDecryptor;
import net.rim.device.api.crypto.BlockEncryptor;
import net.rim.device.api.crypto.CryptoTokenSymmetricKeyData;
import net.rim.device.api.crypto.FIPS186PseudoRandomSource;
import net.rim.device.api.crypto.InitializationVector;
import net.rim.device.api.crypto.PKCS5UnformatterEngine;
import net.rim.device.api.crypto.RandomSource;
import net.rim.device.api.io.Base64InputStream;
import net.rim.device.api.io.Base64OutputStream;
import net.rim.device.api.util.DataBuffer;

import com.phyder.fwk.exhandler.CustomLogger;
import com.phyder.fwk.exhandler.CustomNonFatalException;

public class SymmetricAlgoUtil {

	public static String AES_KEY="";
	public static String AES_IV="";

	public static void generateNewKey(){
		try{
		byte[] byteKey=new FIPS186PseudoRandomSource(RandomSource.getBytes(50)).getBytes(32); 
		AES_KEY=Base64OutputStream.encodeAsString(byteKey, 0, byteKey.length, false, false).substring(0, 16);
		byteKey=RandomSource.getBytes(32); 
		AES_IV=Base64OutputStream.encodeAsString(byteKey, 0, byteKey.length, false, false).substring(0, 16);
		byteKey=null;
		}catch(Throwable t){
			t.printStackTrace();
		}
	}

	public static void flushKey(){
		try{
			AES_KEY=null;
		}catch(Throwable t){
			t.printStackTrace();
		}
	}
	
	public static String encryptData(String strPlainText) {
		try {
			if(AES_KEY==null){
				throw new CustomNonFatalException("Application does not have all security permissions");
			}
			AESKey key = new AESKey(AES_KEY.getBytes());
			CryptoTokenSymmetricKeyData keyData = key.getCryptoTokenData();
			InitializationVector iv = new InitializationVector(AES_IV.getBytes());
			AESCBCEncryptorEngine engine = new AESCBCEncryptorEngine(key,
					AESEncryptorEngine.BLOCK_LENGTH_DEFAULT, iv);
			PKCS7FormatterEngine pkcs = new PKCS7FormatterEngine(engine);
			ByteArrayOutputStream output = new ByteArrayOutputStream();
			BlockEncryptor encryptor = new BlockEncryptor(pkcs, output);
			byte[] byteText = strPlainText.getBytes("UTF-8");
			encryptor.write(byteText);
			encryptor.close();
			output.close();
			return Base64OutputStream.encodeAsString(output.toByteArray(), 0,
					output.toByteArray().length, false, false);
		} catch (Throwable t) {
			t.printStackTrace();
		}
		return null;
	}

	public static String decryptData(String strEncryptedText) {

		try {
			if(AES_KEY==null){
				throw new CustomNonFatalException("Application does not have all security permissions");
			}
			AESKey key = new AESKey(AES_KEY.getBytes());
			CryptoTokenSymmetricKeyData keyData = key.getCryptoTokenData();
			InitializationVector iv = new InitializationVector(AES_IV.getBytes());
			AESCBCDecryptorEngine engine = new AESCBCDecryptorEngine(key,AESEncryptorEngine.BLOCK_LENGTH_DEFAULT, iv);
			ByteArrayOutputStream output = new ByteArrayOutputStream();
			PKCS5UnformatterEngine pkcs = new PKCS5UnformatterEngine(engine);
			ByteArrayInputStream inputStream = new ByteArrayInputStream(
					Base64InputStream.decode(strEncryptedText));
			BlockDecryptor decryptor = new BlockDecryptor(pkcs, inputStream);
			final byte[] temp = new byte[10];
			final DataBuffer db = new DataBuffer();
			for (;;) {
				final int bytesRead = decryptor.read(temp);

				if (bytesRead <= 0) {
					// We have run out of information to read, bail out of loop
					break;
				}
				db.write(temp, 0, bytesRead);
			}
			final byte[] decryptedData = db.toArray();
			final String decryptedText = new String(decryptedData);
			decryptor.close();
			output.close();
			return decryptedText;
		} catch (Throwable t) {
			t.printStackTrace();
		}
		return null;
	}

}
