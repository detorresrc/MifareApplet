package com.detorresrc.main;

import com.detorresrc.mifare.IMifareCard;
import com.detorresrc.mifare.MifareResponseCodes;
import com.detorresrc.mifare.MifareResponseData;
import com.detorresrc.reader.CardNotSupportedException;
import com.detorresrc.reader.Reader;

public class Main {

	public static void main(String[] args) {
		// TODO Auto-generated method stub

		Reader reader = new Reader();
		
		int ret;
		
		ret = reader.ConnectToReader();
		
		System.out.println("Ret : " + ret);
		
		if( ret == MifareResponseCodes.MF_SUCCESS ){
			System.out.println("Connected to reader : " + reader.GetReaderName() );
		}
	
		ret = reader.ConnectToCard("T=1");
		if( ret == MifareResponseCodes.MF_SUCCESS ){
			System.out.println("Connected to Card!");
		}else{
			System.out.println("Ret : " + ret);
		}
		
		IMifareCard card = null;
		try {
			card = reader.GetCard();
			System.out.println("Cardname : " + card.getCardName() );
		} catch (CardNotSupportedException e) {
			// TODO Auto-generated catch block
			System.out.println(e.getMessage());
		}
		
//		MifareResponseData responseDataBlocks = card.ReadTrailingBlocks(reader);
//		if(responseDataBlocks.ReturnCode == MifareResponseCodes.MF_SUCCESS){
//			System.out.println( Util.bytesToHex(responseDataBlocks.data) );
//		}
		
		
		System.out.println("Ret : " + card.ResetCard(reader));
		
//		System.out.println("Ret : " + card.Initialize(reader));
		
//		ret = card.Write(reader, "ROMMEL DE TORRES|31".getBytes());
//		System.out.println("Write Ret : " + ret);
//		
//		MifareResponseData responseData = card.Read(reader);
//		System.out.println("Read Ret : " + responseData.ReturnCode);
//		
//		System.out.println( ">" + Util.bytesToChar(responseData.data) + "<" );
		
//		ret = card.AuthBlock(reader, (byte)0x3E, card.GetKeyA(), (byte)0x60);
//		System.out.println("Auth Ret : " + ret);
		
//		MifareResponseData hashResponseData = card.ReadBlock(reader, (byte)0x3E);
//		System.out.println("Hash Read Ret : " + hashResponseData.ReturnCode);
//		System.out.println( "READ DIGEST >> " + Util.bytesToHex(hashResponseData.data) );
		
		/*
		ret = card.AuthBlock(reader, (byte)0x01, card.GetKeyA(), (byte)0x60);
		System.out.println("Ret : " + ret);
		if( ret == MifareResponseCodes.MF_SUCCESS ){
			MifareResponseData responseData = card.ReadBlock(reader, (byte)0x01);
			
			System.out.println("Ret : " + responseData.ReturnCode);
			
			if( responseData.ReturnCode == MifareResponseCodes.MF_SUCCESS ){
				System.out.println( Util.bytesToHex(responseData.data) );
				System.out.println( Util.bytesToChar(responseData.data) );
			}
		}
		
		ret = card.WriteBlock(
				reader,
				(byte)0x01,
				"ROMMELDETORRES".getBytes()
		);
		System.out.println("Ret : " + ret);
		*/
		
		
		
	}

}
