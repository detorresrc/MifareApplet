package com.detorresrc.mifarecard;


public class Mifare1K extends MifareClassicBase {
	public Mifare1K(){
		this.dataSize = 735; // Reserved 1 byte for EndOfText
		
		this.hashDataBLockAddress = (byte)0x3E;
		
		this.cardName = "Mifare 1K";
		
		this.trailingBlockAddress = new byte[16];
		this.trailingBlockAddress[0]=(byte)0x03;
		this.trailingBlockAddress[1]=(byte)0x07;
		this.trailingBlockAddress[2]=(byte)0x0B;
		this.trailingBlockAddress[3]=(byte)0x0F;
		this.trailingBlockAddress[4]=(byte)0x13;
		this.trailingBlockAddress[5]=(byte)0x17;
		this.trailingBlockAddress[6]=(byte)0x1B;
		this.trailingBlockAddress[7]=(byte)0x1F;
		this.trailingBlockAddress[8]=(byte)0x23;
		this.trailingBlockAddress[9]=(byte)0x27;
		this.trailingBlockAddress[10]=(byte)0x2B;
		this.trailingBlockAddress[11]=(byte)0x2F;
		this.trailingBlockAddress[12]=(byte)0x33;
		this.trailingBlockAddress[13]=(byte)0x37;
		this.trailingBlockAddress[14]=(byte)0x3B;
		this.trailingBlockAddress[15]=(byte)0x3F;
		
		this.dataBlockAddress = new byte[46];
		this.dataBlockAddress[0]=(byte)0x01;
		this.dataBlockAddress[1]=(byte)0x02;
		this.dataBlockAddress[2]=(byte)0x04;
		this.dataBlockAddress[3]=(byte)0x05;
		this.dataBlockAddress[4]=(byte)0x06;
		this.dataBlockAddress[5]=(byte)0x08;
		this.dataBlockAddress[6]=(byte)0x09;
		this.dataBlockAddress[7]=(byte)0x0A;
		this.dataBlockAddress[8]=(byte)0x0C;
		this.dataBlockAddress[9]=(byte)0x0D;
		this.dataBlockAddress[10]=(byte)0x0E;
		this.dataBlockAddress[11]=(byte)0x10;
		this.dataBlockAddress[12]=(byte)0x11;
		this.dataBlockAddress[13]=(byte)0x12;
		this.dataBlockAddress[14]=(byte)0x14;
		this.dataBlockAddress[15]=(byte)0x15;
		this.dataBlockAddress[16]=(byte)0x16;
		this.dataBlockAddress[17]=(byte)0x18;
		this.dataBlockAddress[18]=(byte)0x19;
		this.dataBlockAddress[19]=(byte)0x1A;
		this.dataBlockAddress[20]=(byte)0x1C;
		this.dataBlockAddress[21]=(byte)0x1D;
		this.dataBlockAddress[22]=(byte)0x1E;
		this.dataBlockAddress[23]=(byte)0x20;
		this.dataBlockAddress[24]=(byte)0x21;
		this.dataBlockAddress[25]=(byte)0x22;
		this.dataBlockAddress[26]=(byte)0x24;
		this.dataBlockAddress[27]=(byte)0x25;
		this.dataBlockAddress[28]=(byte)0x26;
		this.dataBlockAddress[29]=(byte)0x28;
		this.dataBlockAddress[30]=(byte)0x29;
		this.dataBlockAddress[31]=(byte)0x2A;
		this.dataBlockAddress[32]=(byte)0x2C;
		this.dataBlockAddress[33]=(byte)0x2D;
		this.dataBlockAddress[34]=(byte)0x2E;
		this.dataBlockAddress[35]=(byte)0x30;
		this.dataBlockAddress[36]=(byte)0x31;
		this.dataBlockAddress[37]=(byte)0x32;
		this.dataBlockAddress[38]=(byte)0x34;
		this.dataBlockAddress[39]=(byte)0x35;
		this.dataBlockAddress[40]=(byte)0x36;
		this.dataBlockAddress[41]=(byte)0x38;
		this.dataBlockAddress[42]=(byte)0x39;
		this.dataBlockAddress[43]=(byte)0x3A;
		this.dataBlockAddress[44]=(byte)0x3C;
		this.dataBlockAddress[45]=(byte)0x3D;
	}
}
