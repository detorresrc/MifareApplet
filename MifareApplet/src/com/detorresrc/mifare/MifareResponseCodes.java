package com.detorresrc.mifare;

public class MifareResponseCodes {
	
	public final static int MF_CARD_EXCEPTION_ERROR = 1000; // Card Exception Error
	
	public final static int MF_SUCCESS = 10001; // Success
	
	public final static int MF_INVALID_KEY_SIZE = 10002; // Invalid Key Size
	
	public final static int MF_NO_READER_FOUND = 10003; // No Reader Found
	
	public final static int MF_NO_SUPPLIED_BUFFER = 10004; // No Supplied Buffer
	
	public final static int MF_AUTH_SEND_ERROR = 10005; // Sending Auth to Reader Error
	
	public final static int MF_AUTH_ERROR = 10006; // Auth Error
	
	public final static int MF_READ_BLOCK_ERROR = 10007; // Read Block Error
	
	public final static int MF_WRITE_BLOCK_ERROR = 10008; // Read Block Error
}