package com.detorresrc.mifare;

public class MifareResponseData {
	public int ReturnCode;
	public byte[] data;
	
	public MifareResponseData(){
		ReturnCode = 0;
		data = null;
	}
}
