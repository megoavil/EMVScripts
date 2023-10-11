package emvdemo;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;

public class Cvn18 {
	private String MKAC;

	/**
	 * @return the mKAC
	 */
	public String getMKAC() {
		return MKAC;
	}

	/**
	 * @param mKAC the mKAC to set
	 */
	public void setMKAC(String mKAC) {
		MKAC = mKAC;
	}

	public Cvn18(String mKAC) {
		super();
		MKAC = mKAC;
	}
	
	public String calculateARQC(String pan,
			String PSN,
			String ARQC,
			String AMMOUNT_AUTH,
			String AMMOUNT_OTHER,
			String TERM_COUNTRY_CODE,
			String TVR,
			String TXN_CURRENCY_CODE,
			String TXN_DATE,
			String TXN_TYPE,
			String UNPR_NUMBER,
			String AIP,
			String ATC,
			String IAD) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
		
		//Construccion de los datos de entrada para el algoritmo de derivacion de llaves
		String PANDATA = (pan+PSN).substring((pan+PSN).length()-16);
		String PANDATA1 = xorHex(PANDATA,"FFFFFFFFFFFFFFFF");

		//Concatenar los datos de entrada
		String ACDATA = AMMOUNT_AUTH
				+ AMMOUNT_OTHER
				+ TERM_COUNTRY_CODE
				+ TVR
				+ TXN_CURRENCY_CODE
				+ TXN_DATE
				+ TXN_TYPE
				+ UNPR_NUMBER
				+ AIP
				+ ATC
				+ IAD;
		//padding de ACDATA de acuerdo a CVN18: using the MAC algorithm specified in Annex A1.2.1 and ISO/IEC 9797-1 Algorithm 3 with DES, and s=8. This method shall be used for a Cryptogram Version of '5'.
		ACDATA = ACDATA + "80";
		int extra = ACDATA.length() % 16;
		if (extra > 0) {
		    for(int i=0;i<16-extra;i++){
		        ACDATA = ACDATA + ("0");
		    }
		}
		
		
		//Crear las partes izquierda y derecha para construir el algoritmo EMV
		//Obtener la llave y darle forma
		String deskey1 = this.MKAC + this.MKAC.substring(0,16);
		SecretKey desKey = new SecretKeySpec(UtilBytes.hex2byte(deskey1),"DESede"); //API ICSF
		Cipher desCipher = Cipher.getInstance("DESede/ECB/NoPadding");
		desCipher.init(Cipher.ENCRYPT_MODE, desKey);
		//Cifrar el PANDATA, construido lineas arriba para obtener la parte izquierda (8bytes)
		byte[] ZL = desCipher.doFinal(
                 UtilBytes.hex2byte(PANDATA));
		//Cifrar el PANDATA1, construido lineas arriba para obtener la parte derecha (8bytes)
		byte[] ZR = desCipher.doFinal(UtilBytes.hex2byte(PANDATA1));
		
		//llave derivada UDK
		String UDKL = UtilBytes.toHEX(ZL);
		String UDKR = UtilBytes.toHEX(ZR);
		String UDK = UDKL + UDKR + UDKL;
		UDK = UDK.replaceAll("\\s+",""); //se remueven los espacios en blanco del UtilBytes
		
		//Llave de sesion
		SecretKey udkKey = new SecretKeySpec(UtilBytes.hex2byte(UDK),"DESede");
		//Inicializar el Cipher con la llave UDK
		desCipher.init(Cipher.ENCRYPT_MODE, udkKey);
		//Construir los datos de derivacion, de acuerdo con EMV Session Key Derivation
		String DerDataL = ATC + "F00000000000";
		String DerDataR = ATC + "0F0000000000";
		//Cifrar los datos de derivacion de la parte izquierda con la llave UDK
		byte[] SKL = desCipher.doFinal(
                UtilBytes.hex2byte(DerDataL));
		//Cifrar los datos de derivacion de la parte derecha con la llave UDK
		byte[] SKR = desCipher.doFinal(UtilBytes.hex2byte(DerDataR));
		//Esta es la llave de sesion
		SecretKey desKeyL = new SecretKeySpec(SKL,"DES");
		SecretKey desKeyR = new SecretKeySpec(SKR,"DES");
		
		//Algoritmo EMV
		//Inicializar el cipher con la llave izquierda
		Cipher desCipher1 = Cipher.getInstance("DES/ECB/NoPadding");
		desCipher1.init(Cipher.ENCRYPT_MODE, desKeyL);
		//Algoritmo MAC para la generacion de ARQC
		//Paso 1: Ejecutar la transformacion inicial 1 del algoritmo iso 9797-1 y la iteracion
		byte[] aux1= {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00}, aux2;
		for(int i=0;i<UtilBytes.hex2byte(ACDATA).length/8;i++) {
			int beg = i*8;

			byte[] subarray = new byte[8];
	        System.arraycopy(UtilBytes.hex2byte(ACDATA), beg, subarray, 0, subarray.length);
			aux2 = xorByte(subarray,aux1);
	        aux1 = desCipher1.doFinal(aux2);
		}
		
		//Paso 2: Ejecutar la transformacion de salida 3 del algoritmo iso 9797-1.
		//		  El resultado será el ARQC, TC o AAC
		desCipher1.init(Cipher.DECRYPT_MODE, desKeyR);
		aux1 = desCipher1.doFinal(aux1);
		desCipher1.init(Cipher.ENCRYPT_MODE, desKeyL);
		aux1 = desCipher1.doFinal(aux1);
		
		//Finalmente se devuelve el mensaje de ARQC exitoso o con error
		//ademas del valor calculado
		if (Arrays.equals(aux1, UtilBytes.hex2byte(ARQC))) {
			System.out.println("ARQC Exitoso");
			return UtilBytes.toHEX(aux1); 
		}else {
			System.out.println(UtilBytes.toHEX(aux1));
			System.out.println("Error en validar el ARQC");
			return "Error en validar el ARQC";
		}
		
	}
	
	public String generaARPC(String ARQC, String CSU, String pan, String PSN, String ATC) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
		
		String PANDATA = (pan+PSN).substring((pan+PSN).length()-16);
		String PANDATA1 = xorHex(PANDATA,"FFFFFFFFFFFFFFFF");
		
		//Crear las partes izquierda y derecha para construir el algoritmo EMV
		String deskey1 = this.MKAC + this.MKAC.substring(0,16);
		//System.out.println(deskey1);
		SecretKey desKey = new SecretKeySpec(UtilBytes.hex2byte(deskey1),"DESede"); //API ICSF
		Cipher desCipher = Cipher.getInstance("DESede/ECB/NoPadding");
		desCipher.init(Cipher.ENCRYPT_MODE, desKey);
		byte[] ZL = desCipher.doFinal(
                 UtilBytes.hex2byte(PANDATA));
		byte[] ZR = desCipher.doFinal(UtilBytes.hex2byte(PANDATA1));
		
		//Derivacion de la llave de sesion
		String UDKL = UtilBytes.toHEX(ZL);
		String UDKR = UtilBytes.toHEX(ZR);
		String UDK = UDKL + UDKR + UDKL;
		UDK = UDK.replaceAll("\\s+","");
		SecretKey udkKey = new SecretKeySpec(UtilBytes.hex2byte(UDK),"DESede");
		desCipher.init(Cipher.ENCRYPT_MODE, udkKey);
		String DerDataL = ATC + "F00000000000"; //parte izquierda
		String DerDataR = ATC + "0F0000000000"; //parte derecha
		byte[] SKL = desCipher.doFinal(
                UtilBytes.hex2byte(DerDataL));
		byte[] SKR = desCipher.doFinal(UtilBytes.hex2byte(DerDataR));
		//Esta es la llave de sesion
		SecretKey desKeyL = new SecretKeySpec(SKL,"DES");
		SecretKey desKeyR = new SecretKeySpec(SKR,"DES");
		
		//Preparamos los datos y aplicamos el algoritmo 3DES
		String Y = ARQC + CSU;
		//padding de ACDATA de acuerdo a CVN18: using the MAC algorithm specified in Annex A1.2.1 and ISO/IEC 9797-1 Algorithm 3 with DES, and s=8. This method shall be used for a Cryptogram Version of '5'.
		Y = Y + "80";
		int extra = Y.length() % 16;
		if (extra > 0) {
		    for(int i=0;i<16-extra;i++){
		        Y = Y + ("0");
		    }
		}
		
		//Ingresar los datos por bloques de 8 bytes, cifrarlos y aplicar XOR con el siguiente grupo
		Cipher desCipher1 = Cipher.getInstance("DES/ECB/NoPadding");
		desCipher1.init(Cipher.ENCRYPT_MODE, desKeyL);
		byte[] aux2= {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00}, aux3;
		
		//loop principal con la parte izquierda de la llave
		for(int i=0;i<UtilBytes.hex2byte(Y).length/8;i++) {
			int beg = i*8;

			byte[] subarray = new byte[8];
	        System.arraycopy(UtilBytes.hex2byte(Y), beg, subarray, 0, subarray.length);
			aux3 = xorByte(subarray,aux2);
	        aux2 = desCipher1.doFinal(aux3);
		}
		
		desCipher1.init(Cipher.DECRYPT_MODE, desKeyR);
		aux2 = desCipher1.doFinal(aux2);
		desCipher1.init(Cipher.ENCRYPT_MODE, desKeyL);
		aux2 = desCipher1.doFinal(aux2);
		//Se devuelve el ARPC como un String
		return UtilBytes.toHEX(aux2);
		
		
		
	}
	
	private static byte[] xorByte(byte[] a, byte[] b) {
		
		byte[] array_3 = new byte[8];

		int i = 0;
		for (byte j : a)
		    array_3[i] = (byte) (j ^ b[i++]);
		
		return array_3;
	}

	public static String ARPCVisav10(String pan,
		String PSN,
		String ARQC,
		String ARC) {
		
		return "TODO";
	}
	
	private static String xorHex(String a, String b) {
	    // TODO: Validation
	    char[] chars = new char[a.length()];
	    for (int i = 0; i < chars.length; i++) {
	        chars[i] = toHex(fromHex(a.charAt(i)) ^ fromHex(b.charAt(i)));
	    }
	    return new String(chars);
	}
	
	private static int fromHex(char c) {
	    if (c >= '0' && c <= '9') {
	        return c - '0';
	    }
	    if (c >= 'A' && c <= 'F') {
	        return c - 'A' + 10;
	    }
	    if (c >= 'a' && c <= 'f') {
	        return c - 'a' + 10;
	    }
	    throw new IllegalArgumentException();
	}

	private static char toHex(int nybble) {
	    if (nybble < 0 || nybble > 15) {
	        throw new IllegalArgumentException();
	    }
	    return "0123456789ABCDEF".charAt(nybble);
	}


}
