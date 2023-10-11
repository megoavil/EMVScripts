package emvdemo;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;


public class EMVService {

	public static void main(String[] args) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {
		
		Cvn10 cvn10 = new Cvn10("DF00111111110101DF00111111110202"); // DATO A PROTEGER PCI PIN
		
		
		
		
		System.out.println("EL ARQC en CVN10 es: "+cvn10.calculateARQC("4924910104613794", // DATO A PROTEGER PCI DSS
				"01",
				 "4414E8DEE3AEE168", //ARQC REcibido
				 "000000000000", //monto autorizado
				 "000000000000", //monto otro
				 "0604", //codigo de pais
				 "0080048000", // TVR
				 "0604", // codigo de terminal pais
				 "210212", //fecha
				 "00", //tipo de servicio
				 "0523F18A", //numero impredecible
				 "3C00", //AIP
				 "00DD", //ATC
				 "03A0A801")); //CVR
		
		System.out.println("EL ARPC en CVN10 es: "+cvn10.generaARPC("4414E8DEE3AEE168", //ARQC 
				"3030", //ARC
				"4924910104613794", //PAN
				"01")); //PSN
		
		
		

		Cvn18 cvn18 = new Cvn18("DF00111111110101DF00111111110202"); // DATO A PROTEGER PCI PIN
		
		
		
		
		System.out.println("EL ARQC en CVN18 es: "+cvn18.calculateARQC("0006005001284978", // PAN 
				"01", //PSN
				 "BDFD60DAA1C34DF1", //ARQC Recibido
				 "000000001000", //9F02 monto autorizado long 06
				 "000000000000", //9F03 monto otro long 06
				 "0604", //9F1A codigo de pais long 02
				 "0880008000", //95 TVR long 05
				 "0604", //5F2A codigo de terminal pais long 02
				 "210923", //9A fecha long 03
				 "00", //9C tipo de servicio long 01
				 "33D4E892", //9F37 numero impredecible long 04
				 "3C00", //82 AIP long 02
				 "002D", //9F36 ATC long 02
				 "06011203A0B801")); //9F10 IAD long 07
		
		System.out.println("EL ARPC en CVN18 es: "+cvn18.generaARPC("4414E8DEE3AEE168", //ARQC 
				"00000000", //CSU
				"4924910104613794", //PAN
				"01", //PSN
				"00DD")); //ATC
		
		

	}

}
