package com.detorresrc.mifarecard;

import java.util.ArrayList;
import java.util.List;

import com.detorresrc.mifare.IMifareCard;
import com.detorresrc.mifare.MifareResponseCodes;
import com.detorresrc.mifare.MifareResponseData;
import com.detorresrc.reader.Reader;
import com.detorresrc.reader.ReaderTransmitResponse;

public class MifareClassicBase implements IMifareCard{
	
	protected int dataSize = 0;
	
	protected byte[] dataBlockAddress;
	protected byte hashDataBLockAddress;
	protected byte[] trailingBlockAddress;
	
	protected final byte[] keyA = {
		(byte)0x05, (byte)0x20, (byte)0x84, (byte)0x84, (byte)0x20, (byte)0x05
	};
	protected final byte[] keyB = {
		(byte)0x05, (byte)0x05, (byte)0x20, (byte)0x20, (byte)0x84, (byte)0x84
	};
	
	protected final byte[] defaultKeyA = {
		(byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF
	};
	protected final byte[] defaultKeyB = {
		(byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF
	};
	
	protected String protocol = "T=1";
	
	protected String cardName = "";
	
	protected byte numberBytesToReadAndWrite = 0x10; // 16 Bytes
	
	protected byte endOfText = 0x03;
	
	protected int bytesPerBlock = 16;
	
	public String getCardName(){
		return this.cardName;
	}
	
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
		mifareResponse.ReturnCode = MifareResponseCodes.MF_SUCCESS;
		
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
		
		if( data.length > this.numberBytesToReadAndWrite ){
			return MifareResponseCodes.MF_WRITE_INVALID_BUFFER_SIZE;
		}
		
		for(int i=0; i<16; i++){
			buffAPDUWrite[5+i] = 0x00;
		}
		for( int i=0; i<data.length; i++ ){
			buffAPDUWrite[5+i] = data[i];
		}
		
		ReaderTransmitResponse transmitResponse = reader.Trasmit(buffAPDUWrite);
		if( transmitResponse.reponseCode != MifareResponseCodes.MF_SUCCESS ){
			return transmitResponse.reponseCode;
		}
		if( ((byte)transmitResponse.reponseAPDU.getSW1() == (byte)0x90 && (byte)transmitResponse.reponseAPDU.getSW2() == (byte)0x00) == false ){
			return MifareResponseCodes.MF_WRITE_BLOCK_ERROR;
		}
		
		return MifareResponseCodes.MF_SUCCESS;
	}

	@Override
	public MifareResponseData Read(Reader reader) {
		List<Byte> byteList = new ArrayList<Byte>();
		
		MifareResponseData responseData = new MifareResponseData();
		
		responseData.ReturnCode = MifareResponseCodes.MF_SUCCESS;
		
		int ret;
		boolean breakParentLoop = false;
		for( int i=0; i<this.dataBlockAddress.length; i++ ){
			
			// Auth Block
			ret = this.AuthBlock(
					reader,
					this.dataBlockAddress[i], this.keyA, (byte)0x60);
			if(ret == MifareResponseCodes.MF_AUTH_ERROR){
				ret = this.AuthBlock(
						reader,
						this.dataBlockAddress[i], this.defaultKeyA, (byte)0x60);
			}
			if(ret == MifareResponseCodes.MF_AUTH_ERROR){
				responseData.ReturnCode = MifareResponseCodes.MF_AUTH_ERROR;
				break;
			}
			
			// Read Block
			MifareResponseData blockResponseData = this.ReadBlock(reader, this.dataBlockAddress[i]);
			
			if( blockResponseData.ReturnCode == MifareResponseCodes.MF_SUCCESS ){
				for(int b=0; b<blockResponseData.data.length; b++){
					if(blockResponseData.data[b]==this.endOfText){
						breakParentLoop = true;
						break;
					}
					byteList.add(blockResponseData.data[b]);
				}
			}else{
				responseData.ReturnCode = blockResponseData.ReturnCode;
				break;
			}
			
			if(breakParentLoop){
				break;
			}
		}//{ for( int i=0; i<this.dataBlockAddress.length; i++ ) }
		
		if( responseData.ReturnCode == MifareResponseCodes.MF_SUCCESS ){
			responseData.data = new byte[ byteList.size() ];
			for(int i=0;i<byteList.size(); i++){
				responseData.data[i] = byteList.get(i);
			}
		}
		
		return responseData;
	}
	
	public int Write(
			Reader reader,
			byte[] data
	){
		int ret = MifareResponseCodes.MF_SUCCESS;
		
		if( data.length > this.dataSize ){
			return MifareResponseCodes.MF_WRITE_INVALID_BUFFER_SIZE;
		}
		
		byte[] dataToWrite = new byte[data.length+1];
		for(int i=0;i<data.length; i++){
			dataToWrite[i] = data[i];
		}
		dataToWrite[data.length] = this.endOfText;
		
		int bBlockCtr=0;
		boolean breakParent = false;
		for( int i=0; i<this.dataBlockAddress.length; i++ ){
			byte[] byteBlock = new byte[this.bytesPerBlock];
			for(int a=0; a<this.bytesPerBlock;a++){
				byteBlock[a] = 0x00;
			}
			int byteBlockCtr = 0;
			for(int e=0; e<this.bytesPerBlock; e++){
				if( (bBlockCtr+1) > dataToWrite.length ){
					breakParent = true;
					break;
				}
				byteBlock[e] = dataToWrite[bBlockCtr];
				bBlockCtr++;
				byteBlockCtr++;
			}
			
			if(byteBlockCtr>0){
				// Auth Block
				ret = this.AuthBlock(
						reader,
						this.dataBlockAddress[i], this.keyA, (byte)0x60);
				if(ret != MifareResponseCodes.MF_SUCCESS){
					ret = this.AuthBlock(
							reader,
							this.dataBlockAddress[i], this.defaultKeyA, (byte)0x60);
				}
				if(ret != MifareResponseCodes.MF_SUCCESS){
					return MifareResponseCodes.MF_AUTH_ERROR;
				}
				
				ret = this.WriteBlock(
						reader,
						this.dataBlockAddress[i],
						byteBlock
				);
				
				if( ret != MifareResponseCodes.MF_SUCCESS ){
					return ret;
				}
			}// { if(byteBlockCtr>0) }
			

			if(breakParent){
				break;
			}
		}//{ for( int i=0; i<this.dataBlockAddress.length; i++ ) }
		
		return ret;
	}
	
	@Override
	public byte[] GetDefaultKeyA() {
		return this.defaultKeyA;
	}

	@Override
	public byte[] GetDefaultKeyB() {
		return this.defaultKeyB;
	}

	@Override
	public byte[] GetKeyA() {
		return this.keyA;
	}

	@Override
	public byte[] GetKeyB() {
		return this.keyB;
	}

	@Override
	public byte[] GetTrailingBlockAddress() {
		return this.trailingBlockAddress;
	}

	@Override
	public byte[] GetDataBlockAddress() {
		return this.dataBlockAddress;
	}

	
}
