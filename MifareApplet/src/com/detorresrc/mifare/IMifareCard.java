package com.detorresrc.mifare;

import com.detorresrc.reader.Reader;

public interface IMifareCard {
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
}
