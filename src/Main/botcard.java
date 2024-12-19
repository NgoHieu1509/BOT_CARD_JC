package Main;

import javacard.framework.*;
import javacard.framework.OwnerPIN;
import javacard.security.*;
import javacardx.crypto.*;
import javacardx.apdu.ExtendedLength;


public class botcard extends Applet implements ExtendedLength
{
	public final static short MAX_SIZE = 16384;
	// Cau hinh PIN
	private final static byte PIN_MIN_SIZE = (byte) 4; // Kich thuoc PIN toi thieu
	private final static byte PIN_MAX_SIZE = (byte) 16; // Kich thuoc PIN toi da
	private final static byte[] PIN_INIT_VALUE = {
		(byte) 'B', (byte) 'o', (byte) 't', 
		(byte) 'c', (byte) 'a', (byte) 'r', (byte) 'd'};
		
		
	//thong tin nguoi dung
	public static byte[] infoID;
	public static short lenID;	
	public static byte[] infoName;
	public static short lenName = 0;
	public static byte[] infoDob;
	public static short lenDob = 0;
	public static byte[] infoAddress;
	public static short lenAddress= 0;
	public static byte[] infoNumberPlate;
	public static short lenNumberPlate= 0;
	
	// image
	public static byte[] infoImage;
	private static short receivedBytes;
	private short sentBytes = 0; 

	
	// Byte lenh INS cho cac thao tac khac nhau
	private final static byte INS_SETUP = (byte) 0x2A; // Lenh cau hinh
	private final static byte INS_GEN_KEYPAIR = (byte) 0x30; // Lenh tao cap khoa
	private final static byte INS_CREATE_PIN = (byte) 0x40; // Lenh tao PIN
	private final static byte INS_VERIFY_PIN = (byte) 0x42; // Lenh xac minh PIN
	private final static byte INS_CHANGE_PIN = (byte) 0x44; // Lenh doi PIN
	private final static byte INS_UNBLOCK_PIN = (byte) 0x46; // Lenh mo khoa PIN
	
	private final static byte INS_GET_PUBKEY = (byte) 0x48;
	private final static byte INS_GET_PiRVKEY = (byte) 0x52;
	/////////////////////////////////////////////////
	// APDU data test Huy,2002,HN,12V1-12345
	// 4875792C323030322C484E2C313256312D3132333435
	////////////////////////////////////////////////////
	
	// Lenh INS cho get / set data
	private final static byte INS_SET_DATA = 0x01;
	private final static byte INS_GET_DATA = 0x02;
	
	// P1 - INS_GET
	private final static byte P1_GET_NAME = 0x01;
	private final static byte P1_GET_DOB = 0x02;
	private final static byte P1_GET_ADDRESS = 0x03;
	private final static byte P1_GET_NUMBER_PLATE = 0x04;
	private final static byte P1_GET_ID = 0x05;
	
	// INS - Image
	private final static byte INS_SEND_IMAGE = 0x10;	// App -> Card
	private final static byte INS_GET_IMAGE = 0x11; 	// Card -> App
	
	// INS - CHECK STATUS
	private final static byte INS_CHECK = 0x12;	// Check 
	// PIN management
	private static OwnerPIN pin; // PIN hien tais
	private boolean setupDone = false;	
	
	/** ghi trang thai dang nhap*/
	private short loginStatus ;
	private final static byte[] firstLogin = new byte[]{(byte)0x01};		
	private static final byte SEPARATOR = ',';
	
	//crypt
	private AESKey aesKey;
    private RSAPrivateKey rsaPrivateKey;
    private RSAPublicKey rsaPublicKey;
    private byte[] RSA_MODULUS;
    private static short LENGTH_BLOCK_AES = (short)32;
    
    private byte[] encryptedId;
    private byte[] encryptedName;
    private byte[] encryptedDob;
    private byte[] encryptedAddress;
    private byte[] encryptednumberPlate;

	/** Tra ve loi 9C0F khi tham so khong hop le */
	private final static short SW_INVALID_PARAMETER = (short) 0x9C0F;
	/** Tra ve loi 9C0C khi the bi khoa */
	private final static short SW_IDENTITY_BLOCKED = (short) 0x9C0C;
	/** Tra ve loi 9C02 khi nhap sai ma PIN */
	private final static short SW_AUTH_FAILED = (short) 0x9C02;
	/** Tra ve loi khi PIN khong bi khoa */
	private final static short SW_OPERATION_NOT_ALLOWED = (short) 0x9C03;
	/** Loi noi bo */
	private final static short SW_INTERNAL_ERROR = (short) 0x9CFF;
	/** Tra ve loi 9C04 khi the chua duoc cai dat */
	private final static short SW_SETUP_NOT_DONE = (short) 0x9C04;
	/** Loi tham so P1 */
	private final static short SW_INCORRECT_P1 = (short) 0x9C10;
	/** Loi tham so P2 */
	private final static short SW_INCORRECT_P2 = (short) 0x9C11;
	/** Thao tac khong duoc phep vi thieu quyen */
	private final static short SW_UNAUTHORIZED = (short) 0x9C06;
	/** Thuat toan duoc chi dinh khong dung */
	private final static short SW_INCORRECT_ALG = (short) 0x9C09;

	
	
	public botcard(){
		if (!KiemTraDoDaiPIN(PIN_INIT_VALUE, (short) 0, (byte) PIN_INIT_VALUE.length))
		    ISOException.throwIt(SW_INTERNAL_ERROR);
		    
		// Initialize these arrays here
		infoID = new byte[16];
		infoName = new byte[64];
		infoDob = new byte[32];
		infoAddress = new byte[32];
		infoNumberPlate = new byte[16];
				
		lenID = 0;
		lenAddress = 0;
		lenName = 0;
		lenDob = 0;
		lenNumberPlate = 0;	
		infoImage = new byte[MAX_SIZE];
		
		aesKey = null;
        rsaPrivateKey = null;
        rsaPublicKey = null;
        RSA_MODULUS = new byte[128];
        generateRSAKeys();
        
		pin = new OwnerPIN((byte) 3, (byte) PIN_INIT_VALUE.length);
		pin.update(PIN_INIT_VALUE, (short) 0, (byte) PIN_INIT_VALUE.length);	
	}
	
	public static void install(byte[] bArray, short bOffset, byte bLength) 
	{
		new botcard().register(bArray, (short) (bOffset + 1), bArray[bOffset]);;
	}
	public boolean select() {
		LogOut();
		return true;
	}

	public void deselect() {
		LogOut();
	}
	public void process(APDU apdu)
	{
		
		byte[] buf = apdu.getBuffer();
		
		 if (selectingApplet()){
			CheckFisrtUse(apdu,buf);
			ISOException.throwIt(ISO7816.SW_NO_ERROR);
		}
		
		//apdu.setIncomingAndReceive();
		
		
		if ((buf[ISO7816.OFFSET_CLA] == 0) && (buf[ISO7816.OFFSET_INS] == (byte) 0xA4))
			return;		
		
		short pointer = 0;
		
		switch (buf[ISO7816.OFFSET_INS])
		{
		case INS_SETUP:
			setup(apdu,buf);
			break;
		case (byte) 0x70:
			setupPin(apdu);
			break;
		case INS_CREATE_PIN:
			CreatePIN(apdu,buf);
			break;
		case INS_VERIFY_PIN:
			VerifyPIN(apdu,buf);
			break;
		case INS_CHANGE_PIN:
			ChangePIN(apdu,buf);
			break;
		case INS_UNBLOCK_PIN:
			UnblockPIN(apdu,buf);
			break;
		case INS_GET_PUBKEY:
            sendPublicKey(apdu);
            break;
        case INS_GET_PiRVKEY:
            sendPrivateKey(apdu);
            break;
		case INS_SET_DATA:
			setData(apdu);
			break;
		case INS_GET_DATA:
			//getData(apdu);
			short p1 = buf[ISO7816.OFFSET_P1];
			switch(p1) {
				case P1_GET_NAME:
					getData(apdu, infoName, lenName);
					break;
				case P1_GET_DOB:
					getData(apdu, infoDob, lenDob);
					break;
				case P1_GET_ADDRESS:
					getData(apdu, infoAddress, lenAddress);
					break;
				case P1_GET_NUMBER_PLATE:
					getData(apdu, infoNumberPlate, lenNumberPlate);
					break;
				case P1_GET_ID:
					getData(apdu, infoID, lenID);
					break;
				default:
					ISOException.throwIt(ISO7816.SW_DATA_INVALID);
			}
			break;
		case INS_SEND_IMAGE: // Nhan anh tu application -> card
			receiveChunk(apdu);
			break;
		case INS_GET_IMAGE: // Xuat anh tu card -> application
			sendChunk(apdu);
			break;
		case INS_CHECK:
			if(!setupDone) {
				ISOException.throwIt(SW_SETUP_NOT_DONE);
			} else {
				buf[0] = 0x01;
			}
			
			apdu.setOutgoingAndSend((short)0, (short)1);
			break;
		default:
			ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
		}
	}
	
	
	private void setup(APDU apdu, byte[] buffer) {
		firstLogin[0] = (byte)0x00;
		setupDone = true;
	}
	private void setupPin(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        apdu.setIncomingAndReceive();
        short pinOffset = ISO7816.OFFSET_CDATA;
        byte pinLength = buffer[ISO7816.OFFSET_LC];

        if (pinLength <= 0 || pinLength > PIN_MAX_SIZE) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }

        pin.update(buffer, pinOffset, pinLength);
        if (!pin.check(buffer, pinOffset, pinLength)) {
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }

        byte[] aesKeyBuffer = JCSystem.makeTransientByteArray((short) 32, JCSystem.CLEAR_ON_RESET); // 256-bit (32 byte)
        MessageDigest sha = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);
        sha.doFinal(buffer, pinOffset, pinLength, aesKeyBuffer, (short) 0);

        aesKey = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_128, false);
        aesKey.setKey(aesKeyBuffer, (short) 0); 
    }

	
	private void CreatePIN(APDU apdu, byte[] buffer) {
		/* Kiem tra dang nhap */
		short lenBytePin = Util.makeShort((byte) 0x00, buffer[ISO7816.OFFSET_LC]); // 05
		if (lenBytePin != apdu.setIncomingAndReceive())
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		// toi thieu 1 byte so size pin va 1 byte pin code
		if (lenBytePin < (short)2)
			ISOException.throwIt(SW_INVALID_PARAMETER);
			
		byte pinSize = buffer[ISO7816.OFFSET_CDATA]; // 04
		if (lenBytePin < (short) (1 + pinSize))
			ISOException.throwIt(SW_INVALID_PARAMETER);
		if (!KiemTraDoDaiPIN(buffer, (short) (ISO7816.OFFSET_CDATA + 1), pinSize))
			ISOException.throwIt(SW_INVALID_PARAMETER);
			
		pin = new OwnerPIN((byte)3, PIN_MAX_SIZE);
		pin.update(buffer, (short) (ISO7816.OFFSET_CDATA + 1), pinSize);	
	}
	
	private void VerifyPIN(APDU apdu, byte[] buffer) {
		if (pin == null)
			ISOException.throwIt(SW_INCORRECT_P1);
			
		if (buffer[ISO7816.OFFSET_P2] != 0x00)
			ISOException.throwIt(SW_INCORRECT_P2);
			
		short lenBytePin = Util.makeShort((byte) 0x00, buffer[ISO7816.OFFSET_LC]);
		
		if (lenBytePin != apdu.setIncomingAndReceive())
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
			
		if (!KiemTraDoDaiPIN(buffer, ISO7816.OFFSET_CDATA, (byte) lenBytePin))
			ISOException.throwIt(SW_INVALID_PARAMETER);
			
		if (pin.getTriesRemaining() == (byte) 0x00)
			ISOException.throwIt(SW_IDENTITY_BLOCKED);
			
		if (!pin.check(buffer, (short) ISO7816.OFFSET_CDATA, (byte) lenBytePin)) {
			LogOut();
			ISOException.throwIt(SW_AUTH_FAILED);
		}
		loginStatus  = (short) 0x0010;
	}
	
	private void ChangePIN(APDU apdu, byte[] buffer) {
		if (pin == null)
			ISOException.throwIt(SW_INCORRECT_P1);
		if (buffer[ISO7816.OFFSET_P2] != (byte) 0x00)
			ISOException.throwIt(SW_INCORRECT_P2);
			
		short lenBytePin = Util.makeShort((byte) 0x00, buffer[ISO7816.OFFSET_LC]);
		if (apdu.setIncomingAndReceive() != lenBytePin)
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		
		if (lenBytePin < (short)4)
			ISOException.throwIt(SW_INVALID_PARAMETER);
			
		byte pinSize = buffer[ISO7816.OFFSET_CDATA];
		if (lenBytePin < (short) (1 + pinSize))
			ISOException.throwIt(SW_INVALID_PARAMETER);
			
		if (!KiemTraDoDaiPIN(buffer, (short) (ISO7816.OFFSET_CDATA + 1), pinSize))
			ISOException.throwIt(SW_INVALID_PARAMETER);
			
		byte newPinSize = buffer[(short) (ISO7816.OFFSET_CDATA + 1 + pinSize)];
		if (lenBytePin < (short) (1 + pinSize + newPinSize))
			ISOException.throwIt(SW_INVALID_PARAMETER);
			
		if (!KiemTraDoDaiPIN(buffer, (short) (ISO7816.OFFSET_CDATA + 1 + pinSize + 1), newPinSize))
			ISOException.throwIt(SW_INVALID_PARAMETER);
			
		if (pin.getTriesRemaining() == (byte) 0x00)
			ISOException.throwIt(SW_IDENTITY_BLOCKED);
			
		if (!pin.check(buffer, (short) (ISO7816.OFFSET_CDATA + 1), pinSize)) {
			LogOut();
			ISOException.throwIt(SW_AUTH_FAILED);
		}
		pin.update(buffer, (short)(ISO7816.OFFSET_CDATA + 1 + pinSize + 1), newPinSize);

		loginStatus = (short) 0x0010;
	}
	
	private void UnblockPIN(APDU apdu, byte[] buffer) {
		if (pin == null)
			ISOException.throwIt(SW_INCORRECT_P1);
		// Neu ma PIN khong bi chan, khong hop le
		if (pin.getTriesRemaining() != 0)
			ISOException.throwIt(SW_OPERATION_NOT_ALLOWED);
		if (buffer[ISO7816.OFFSET_P2] != 0x00)
			ISOException.throwIt(SW_INCORRECT_P2);
		short numBytes = Util.makeShort((byte) 0x00, buffer[ISO7816.OFFSET_LC]);
		
		if (numBytes != apdu.setIncomingAndReceive())
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		pin.resetAndUnblock();
	}
	
/*KiemTraDoDaiPIN*/
	private static boolean KiemTraDoDaiPIN(byte[] pin_buffer, short pin_offset, byte pin_size) {
		if ((pin_size < PIN_MIN_SIZE) || (pin_size > PIN_MAX_SIZE))
			return false;
		return true;
	}
	private void CheckFisrtUse(APDU apdu,byte[] buffer){
		apdu.setOutgoing();
		apdu.setOutgoingLength((short)1);
		Util.arrayCopy(firstLogin,(short)0,buffer,(short)0,(short)1);
		apdu.sendBytes((short)0,(short)1);
	}
	private void LogOut() {
		loginStatus  = (short) 0x0000; 
		pin.reset();
	}
	
	// Ham tim vi tri cua dau ngan cach (',' 0x2C)
	private short findDelimiter(byte[] buffer, short offset, short dataLen, byte delimiter) {
		for (short i = offset; i < dataLen; i++) {
			if (buffer[i] == delimiter) {
				return i;
			}
		}
		return dataLen;
	}
	
	// Set data truyen vao cac mang thong tin luu tru
	private void setData(APDU apdu) {
		if (!setupDone) {
			ISOException.throwIt(SW_SETUP_NOT_DONE); // 
		}
		
		byte[] buffer = apdu.getBuffer();
		apdu.setIncomingAndReceive();
		short dataLen = buffer[ISO7816.OFFSET_LC];
		short curPos = 0;
		
		 Util.arrayFillNonAtomic(infoID, (short) 0, (short) infoID.length, (byte) 0);
		Util.arrayFillNonAtomic(infoName, (short) 0, (short) infoName.length, (byte) 0);
		Util.arrayFillNonAtomic(infoDob, (short) 0, (short) infoDob.length, (byte) 0);
		Util.arrayFillNonAtomic(infoAddress, (short) 0, (short) infoAddress.length, (byte) 0);
		Util.arrayFillNonAtomic(infoNumberPlate, (short) 0, (short) infoNumberPlate.length, (byte) 0);
		
		short nextDel = findDelimiter(buffer, (short)ISO7816.OFFSET_CDATA, (short)(ISO7816.OFFSET_CDATA + dataLen), (byte)',');
		lenID = (short)(nextDel - ISO7816.OFFSET_CDATA);
		Util.arrayCopy(buffer, (short)ISO7816.OFFSET_CDATA,infoID,(short)0,lenID);
		
		
		curPos = (short) (nextDel+1);
		nextDel = findDelimiter(buffer,curPos, (short)(ISO7816.OFFSET_CDATA + dataLen), (byte)',');
		lenName = (short)(nextDel - curPos);
		Util.arrayCopy(buffer, curPos, infoName, (short)0, lenName);
		
		
		curPos = (short) (nextDel + 1);
		nextDel = findDelimiter(buffer, curPos, (short)(ISO7816.OFFSET_CDATA + dataLen), (byte)',');
		lenDob = (short)(nextDel - curPos);
		Util.arrayCopy(buffer, curPos, infoDob, (short)0, lenDob);
		
		
		curPos = (short) (nextDel + 1);
		nextDel = findDelimiter(buffer, curPos, (short)(ISO7816.OFFSET_CDATA + dataLen), (byte)',');
		lenAddress = (short)(nextDel - curPos);
		Util.arrayCopy(buffer, curPos, infoAddress, (short)0, lenAddress);
						
		curPos = (short) (nextDel + 1);
		nextDel = findDelimiter(buffer, curPos, (short)(ISO7816.OFFSET_CDATA + dataLen), (byte)',');
		lenNumberPlate = (short)(nextDel - curPos);
		Util.arrayCopy(buffer, curPos, infoNumberPlate, (short)0, lenNumberPlate);
		
		encryptedId = encryptField(infoID, aesKey);
		storeEncryptedField(encryptedId, infoID);
		
		encryptedName = encryptField(infoName, aesKey);
		storeEncryptedField(encryptedName, infoName);

		encryptedDob = encryptField(infoDob, aesKey);
		storeEncryptedField(encryptedDob, infoDob);
		
		encryptedAddress = encryptField(infoAddress, aesKey);
		storeEncryptedField(encryptedAddress, infoAddress);
				
		encryptednumberPlate= encryptField(infoNumberPlate, aesKey);
		storeEncryptedField(encryptednumberPlate, infoNumberPlate);
	}
	
	// dest : Mang chua gia tri, destLength: Do dai mang
	private void getData(APDU apdu,byte[] dest, short destLength) {
		 byte[] buffer = apdu.getBuffer();
		 apdu.setIncomingAndReceive();
		byte[] decryptedData = decryptField(aesKey, dest);
		byte[] trimmedData = removeTrailingZeros(decryptedData);
		short trimmedLength = (short) trimmedData.length;
		apdu.setOutgoing();
		apdu.setOutgoingLength(trimmedLength);
		Util.arrayCopy(trimmedData, (short) 0, buffer, (short) 0, trimmedLength);
		apdu.sendBytes((short) 0, trimmedLength);
	}
	private void receiveChunk(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        short lc = (short) (buffer[ISO7816.OFFSET_LC] & 0xFF); 

        if ((short) (receivedBytes + lc) > MAX_SIZE) {
            ISOException.throwIt(ISO7816.SW_FILE_FULL); 
        }

        // Read data from apdu
        short bytesRead = apdu.setIncomingAndReceive();

        while (bytesRead > 0) {
            Util.arrayCopyNonAtomic(buffer, ISO7816.OFFSET_CDATA, infoImage, receivedBytes, bytesRead);
            receivedBytes += bytesRead;
            bytesRead = apdu.receiveBytes(ISO7816.OFFSET_CDATA);
        }

        
        ISOException.throwIt(ISO7816.SW_NO_ERROR);
    }
    private void sendChunk(APDU apdu) {
		byte[] buffer = apdu.getBuffer();

		// Check receivedBytes != 0
		if (sentBytes >= receivedBytes) {
			// Reset status
			sentBytes = 0;
			ISOException.throwIt(ISO7816.SW_NO_ERROR);
		}

		// Xac dinh size chunk truyen
		short chunkSize = (short) (receivedBytes - sentBytes); // S byte còn li
		if (chunkSize > 243) {
			chunkSize = 243; // Limit size for send
		}

		
		Util.arrayCopyNonAtomic(infoImage, sentBytes, buffer, (short) 0, chunkSize);

		// Update byte send
		sentBytes += chunkSize;

		// Send to application
		apdu.setOutgoing();
		apdu.setOutgoingLength(chunkSize);
		apdu.sendBytes((short) 0, chunkSize);
	}

	 private void generateRSAKeys() {
		KeyPair rsaKeyPair = new KeyPair(KeyPair.ALG_RSA, KeyBuilder.LENGTH_RSA_1024);
		rsaKeyPair.genKeyPair();

		rsaPrivateKey = (RSAPrivateKey) rsaKeyPair.getPrivate();
		rsaPublicKey = (RSAPublicKey) rsaKeyPair.getPublic();

		short modulusLength = rsaPublicKey.getModulus(RSA_MODULUS, (short) 0);

		if (modulusLength != RSA_MODULUS.length) {
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		}
	}	
private void sendPublicKey(APDU apdu) {
		byte[] buffer = apdu.getBuffer();
		apdu.setIncomingAndReceive();

		if (rsaPublicKey == null) {
			ISOException.throwIt(ISO7816.SW_DATA_INVALID);
		}

		short modulusLength = rsaPublicKey.getModulus(buffer, (short) 0);
        short exponentLength = rsaPublicKey.getExponent(buffer, modulusLength);
        short totalLength = (short)(modulusLength + exponentLength);
		apdu.setOutgoingAndSend((short) 0, totalLength);
	}
	
	private void sendPrivateKey(APDU apdu) {
		byte[] buffer = apdu.getBuffer();
		apdu.setIncomingAndReceive();
		Util.arrayFillNonAtomic(buffer, (short) 0, (short) buffer.length, (byte) 0);
		if (rsaPublicKey == null) {
			ISOException.throwIt(ISO7816.SW_DATA_INVALID);
		}
		
		short modulusLength = rsaPrivateKey.getModulus(buffer, (short) 0);
        short exponentLength = rsaPrivateKey.getExponent(buffer, modulusLength);
        short totalLength = (short)(modulusLength + exponentLength);
		apdu.setOutgoingAndSend((short) 0, totalLength);
	}
    private void storeEncryptedField(byte[] encryptedData, byte[] field) {
		Util.arrayCopy(encryptedData, (short) 0, field, (short) 0, (short) encryptedData.length);
	}

	private byte[] encryptField(byte[] field, AESKey aesKey) {
		Cipher cipher = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false);
		cipher.init(aesKey, Cipher.MODE_ENCRYPT);
		byte[] encryptedData = new byte[field.length];
		cipher.doFinal(field, (short) 0, (short) field.length, encryptedData, (short) 0);
		return encryptedData;
	}
	private byte[] decryptField(AESKey aesKey, byte[] field) {
		Cipher cipher = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false);
		byte[] decryptedField = new byte[field.length];
		cipher.init(aesKey, Cipher.MODE_DECRYPT);
		cipher.doFinal(field, (short) 0, (short) field.length, decryptedField, (short) 0);
		return decryptedField;
	}

	private byte[] removeTrailingZeros(byte[] data) {
		short i = (short) (data.length - 1);
			while (i >= 0 && data[i] == (byte) 0x00) {
				i--;
			}
			byte[] trimmedData = new byte[(short) (i + 1)];
			Util.arrayCopyNonAtomic(data, (short) 0, trimmedData, (short) 0, (short) (i + 1));
			return trimmedData;
	}
}