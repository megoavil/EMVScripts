package emvdemo;


import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;




public class Cvn10 {
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

	public Cvn10(String mKAC) {
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
		
		//padding de ACDATA de acuerdo con CVN10
		int extra = ACDATA.length() % 16;
		if (extra > 0) {
		   for(int i=0;i<16-extra;i++){
		       ACDATA = ACDATA + ("0");
		   }
		}
		
		
		//Obtener la llave MDK 3DES (24 bytes) de longitud doble
		String deskey1 = this.MKAC + this.MKAC.substring(0,16);
		SecretKey desKey = new SecretKeySpec(UtilBytes.hex2byte(deskey1),"DESede"); 
		Cipher desCipher = Cipher.getInstance("DESede/ECB/NoPadding");
		//Inicializar el Cipher con la llave MDK
		desCipher.init(Cipher.ENCRYPT_MODE, desKey);
		//Cifrar el PANDATA, construido lineas arriba para obtener la parte izquierda (8bytes)
		byte[] ZL = desCipher.doFinal(
                 UtilBytes.hex2byte(PANDATA));
		//Cifrar el PANDATA1, construido lineas arriba para obtener la parte derecha (8bytes)
		byte[] ZR = desCipher.doFinal(UtilBytes.hex2byte(PANDATA1));
		
		//Asignar los valores resultantes a llaves criptograficas
		SecretKey desKeyL = new SecretKeySpec(ZL,"DES");
		SecretKey desKeyR = new SecretKeySpec(ZR,"DES");
		
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
			System.out.println("Error en validar el ARQC");
			return "Error en validar el ARQC";
		}
		
	}
	
	public String generaARPC(String ARQC, String ARC, String pan, String PSN) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
		byte[] aux1 = xorByte(UtilBytes.hex2byte(ARQC),UtilBytes.hex2byte(ARC+"000000000000"));
		
		String PANDATA = (pan+PSN).substring((pan+PSN).length()-16);
		String PANDATA1 = xorHex(PANDATA,"FFFFFFFFFFFFFFFF");
		
		//Crear las partes izquierda y derecha para construir el algoritmo EMV
		String deskey1 = this.MKAC + this.MKAC.substring(0,16);
		SecretKey desKey = new SecretKeySpec(UtilBytes.hex2byte(deskey1),"DESede"); //API ICSF
		Cipher desCipher = Cipher.getInstance("DESede/ECB/NoPadding");
		desCipher.init(Cipher.ENCRYPT_MODE, desKey);
		byte[] ZL = desCipher.doFinal(
                 UtilBytes.hex2byte(PANDATA));
		byte[] ZR = desCipher.doFinal(UtilBytes.hex2byte(PANDATA1));
		
		//Llave UDK
		String UDKL = UtilBytes.toHEX(ZL);
		String UDKR = UtilBytes.toHEX(ZR);
		String UDK = UDKL + UDKR + UDKL;
		UDK = UDK.replaceAll("\\s+","");
		SecretKey udkKey = new SecretKeySpec(UtilBytes.hex2byte(UDK),"DESede");
		desCipher.init(Cipher.ENCRYPT_MODE, udkKey);
		
		byte[] ARPC = desCipher.doFinal(aux1);
		//El ARPC generado se devuelve como un string
		return UtilBytes.toHEX(ARPC);
		
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
