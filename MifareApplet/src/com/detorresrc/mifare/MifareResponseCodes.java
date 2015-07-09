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
	
	public final static int MF_NO_CARD_FOUND = 10009; // No Card Found
	
	public final static int MF_CARD_NOT_SUPPORTED = 10010; // Inserted Card is not Supported
	
	public final static int MF_WRITE_INVALID_BUFFER_SIZE = 10011; // Invalid Write Buffer Size
	
	public final static int MF_WRITE_MD5_ERROR = 10012; // Invalid Write Buffer Size
	
	public final static int MF_HASH_AUTH_ERROR = 100013; // Hash - Auth Error
	
	public final static int MF_HASH_WRITE_ERROR = 100014; // Hash - Write Error
	
	public final static int MF_READ_UID_ERROR = 100015; // Read UID Error
	
	public final static int MF_READ_UID_NOT_SUPPORTED = 100016; // Read UID Not Supported
	
	public final static int MF_READ_HASH_DATA_ERROR = 100017; // Read Hash Data Error
	
	public final static int MF_READ_HASH_MISMATCH = 100018; // Hash Mismatch
}
