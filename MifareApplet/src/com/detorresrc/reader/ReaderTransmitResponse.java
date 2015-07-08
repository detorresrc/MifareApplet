package com.detorresrc.reader;

import javax.smartcardio.ResponseAPDU;

public class ReaderTransmitResponse {
	public ResponseAPDU reponseAPDU;
	public int reponseCode;
	
	public ReaderTransmitResponse(){
		reponseAPDU = null;
		reponseCode = 0;
	}
}
