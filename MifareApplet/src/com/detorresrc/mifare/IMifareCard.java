package com.detorresrc.mifare;

import com.detorresrc.reader.Reader;

public interface IMifareCard {
	
	public String getCardName();
	
	public byte[] GetDefaultKeyA();
	public byte[] GetDefaultKeyB();
	
	public byte[] GetKeyA();
	public byte[] GetKeyB();
	
	public byte[] GetTrailingBlockAddress();
	public byte[] GetDataBlockAddress();
	
	public int AuthBlock(
			Reader reader,
			byte blockAddress,
			byte[] key,
			byte keyType
	);
	
	public MifareResponseData ReadBlock(
			Reader reader,
			byte blockAddress
	);
	
	public int WriteBlock(
			Reader reader,
			byte blockAddress,
			byte[] data
	);
	
	public MifareResponseData Read(Reader reader);
	public int Write(Reader reader, byte[] data);
}
