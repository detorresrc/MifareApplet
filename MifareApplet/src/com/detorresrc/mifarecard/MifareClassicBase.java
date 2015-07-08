package com.detorresrc.mifarecard;

import com.detorresrc.mifare.IMifareCard;
import com.detorresrc.mifare.MifareResponseCodes;
import com.detorresrc.mifare.MifareResponseData;
import com.detorresrc.reader.Reader;
import com.detorresrc.reader.ReaderTransmitResponse;

public class MifareClassicBase implements IMifareCard{
	
	protected int DATA_SIZE = 0;
	
	protected byte[] dataBlockAddress;
	protected byte[] trailingBlockAddress;
	
	protected byte[] keyA = {
		(byte)0x05, (byte)0x20, (byte)0x84, (byte)0x84, (byte)0x20, (byte)0x05
	};
	protected byte[] keyB = {
		(byte)0x05, (byte)0x05, (byte)0x20, (byte)0x20, (byte)0x84, (byte)0x84
	};
	
	protected byte[] defaultKeyA = {
		(byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF
	};
	protected byte[] defaultKeyB = {
		(byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF
	};
	
	protected String protocol = "T1";
	
	protected byte numberBytesToReadAndWrite = 0x10; // 16 Bytes
	
	public int AuthBlock(
			Reader reader,
			byte blockAddress,
			byte[] key,
			byte keyType
	){
		// Load Authentication Keys to Reader
		byte[] buff = new byte[11];
		buff[0]  = (byte)0xFF; // Class
		buff[1]  = (byte)0x82; // INS
		buff[2]  = (byte)0x00; // P1 - Key Structure
		buff[3]  = (byte)0x00; // P2 - Key Location
		buff[4]  = (byte)0x06; // LC

		if( key.length != 6 ){
			return MifareResponseCodes.MF_INVALID_KEY_SIZE;
		}
		
		// Data Bytes (6 Bytes)
		buff[5]  = key[0];
		buff[6]  = key[1];
		buff[7]  = key[2];
		buff[8]  = key[3];
		buff[9]  = key[4];
		buff[10] = key[5];
		
		ReaderTransmitResponse response = reader.Trasmit(buff);
		if( response.reponseCode != MifareResponseCodes.MF_SUCCESS ){
			return response.reponseCode;
		}
		
		// Check SW1(0x90) and SW2(0x00)
		if( ((byte)response.reponseAPDU.getSW1() == (byte)0x90 && (byte)response.reponseAPDU.getSW2() == (byte)0x00) == false ){
			return MifareResponseCodes.MF_AUTH_SEND_ERROR;
		}
		
		// Auth Block
		byte[] buffAuthBlock = new byte[10];
		buffAuthBlock[0]  = (byte)0xFF; // Class
		buffAuthBlock[1]  = (byte)0x86; // INS
		buffAuthBlock[2]  = (byte)0x00; // P1
		buffAuthBlock[3]  = (byte)0x00; // P2
		buffAuthBlock[4]  = (byte)0x05; // LC
		
		// Data Bytes (5 Bytes)
		buffAuthBlock[5]  = (byte)0x01;   // Version 0x01
		buffAuthBlock[6]  = (byte)0x00; 
		buffAuthBlock[7]  = blockAddress; // Block Number
		buffAuthBlock[8]  = keyType;      // Key Type 0x60 KEY_A 0x61 KEY_B
		buffAuthBlock[9]  = (byte)0x00;   // Key Location
		
		ReaderTransmitResponse responseAuth = reader.Trasmit(buffAuthBlock);
		if( responseAuth.reponseCode != MifareResponseCodes.MF_SUCCESS ){
			return responseAuth.reponseCode;
		}
		
		// Check SW1(0x90) and SW2(0x00)
		if( ((byte)responseAuth.reponseAPDU.getSW1() == (byte)0x90 && (byte)responseAuth.reponseAPDU.getSW2() == (byte)0x00) == false ){
			return MifareResponseCodes.MF_AUTH_ERROR;
		}
		
		return MifareResponseCodes.MF_SUCCESS;
	}
	
	public MifareResponseData ReadBlock(
			Reader reader,
			byte blockAddress
	){
		MifareResponseData mifareResponse = new MifareResponseData();
		mifareResponse.ReturnCode = 1;
		
		byte[] buffAPDURead = new byte[5];
		buffAPDURead[0]  = (byte)0xFF;                     // Class
		buffAPDURead[1]  = (byte)0xB0;                     // INS
		buffAPDURead[2]  = (byte)0x00;                     // P1
		buffAPDURead[3]  = blockAddress;                   // P2 - Block Number
		buffAPDURead[4]  = this.numberBytesToReadAndWrite; // LE - Number of Bytes to Read
		
		ReaderTransmitResponse transmitResponse = reader.Trasmit(buffAPDURead);
		if( transmitResponse.reponseCode != MifareResponseCodes.MF_SUCCESS ){
			mifareResponse.ReturnCode = transmitResponse.reponseCode;
			return mifareResponse;
		}
		if( ((byte)transmitResponse.reponseAPDU.getSW1() == (byte)0x90 && (byte)transmitResponse.reponseAPDU.getSW2() == (byte)0x00) == false ){
			mifareResponse.ReturnCode = MifareResponseCodes.MF_READ_BLOCK_ERROR;
			return mifareResponse;
		}
		
		byte[] tmp = transmitResponse.reponseAPDU.getBytes();
		mifareResponse.data = new byte[16];
		
		// Initialize var
		for(int i=0; i<16; i++){
			mifareResponse.data[i]=(byte)0x00;
		}
		
		// Transfer byte data to response var
		for(int i=0; i<16; i++){
			mifareResponse.data[i]=tmp[i];
		}
		
		return mifareResponse;
	}
	
	public int WriteBlock(
			Reader reader,
			byte blockAddress,
			byte[] data
	){
		
		byte[] buffAPDUWrite = new byte[21];
		
		buffAPDUWrite[0]  = (byte)0xFF;                     // Class
		buffAPDUWrite[1]  = (byte)0xD6;                     // INS
		buffAPDUWrite[2]  = (byte)0x00;                     // P1
		buffAPDUWrite[3]  = blockAddress;                   // P2 - BLock Address
		buffAPDUWrite[4]  = this.numberBytesToReadAndWrite; // LC - Number of Bytes to Update
		
		ReaderTransmitResponse transmitResponse = reader.Trasmit(buffAPDUWrite);
		if( transmitResponse.reponseCode != MifareResponseCodes.MF_SUCCESS ){
			return transmitResponse.reponseCode;
		}
		if( ((byte)transmitResponse.reponseAPDU.getSW1() == (byte)0x90 && (byte)transmitResponse.reponseAPDU.getSW2() == (byte)0x00) == false ){
			return MifareResponseCodes.MF_WRITE_BLOCK_ERROR;
		}
		
		return MifareResponseCodes.MF_SUCCESS;
	}
}
