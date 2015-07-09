package com.detorresrc.reader;

import java.util.List;

import javax.smartcardio.ATR;
import javax.smartcardio.Card;
import javax.smartcardio.CardException;
import javax.smartcardio.CardTerminal;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import javax.smartcardio.TerminalFactory;

import com.detorresrc.mifare.IMifareCard;
import com.detorresrc.mifare.MifareResponseCodes;
import com.detorresrc.mifarecard.Mifare1K;

public class Reader {
	List<CardTerminal> terminals = null;
	CardTerminal terminal = null;
	Card card = null;
	
	public int ConnectToReader(){
		
		TerminalFactory factory = TerminalFactory.getDefault();
		
		try {
			this.terminals = factory.terminals().list();
			
			if( this.terminals.isEmpty() ){
				return MifareResponseCodes.MF_NO_READER_FOUND;
			}
			
			this.terminal = this.terminals.get(0);
		} catch (CardException e) {
			return MifareResponseCodes.MF_CARD_EXCEPTION_ERROR;
		}
		
		return MifareResponseCodes.MF_SUCCESS;
	}
	
	public String GetReaderName(){
		return this.terminal.toString();
	}
	
	public int ConnectToCard(String protocol){
		try {
			
			if( terminal.isCardPresent() == false ){
				return MifareResponseCodes.MF_NO_CARD_FOUND;
			}
			
			card = terminal.connect(protocol);
		} catch (CardException e) {
			return MifareResponseCodes.MF_CARD_EXCEPTION_ERROR;
		}

		return MifareResponseCodes.MF_SUCCESS;
	}
	
	public byte[] GetAtr(){
		ATR atr = card.getATR();
		return atr.getBytes();
	}
	
	public IMifareCard GetCard() throws CardNotSupportedException{
		IMifareCard card;
		
		byte[] atr = this.GetAtr();
		
		// 13 14 Byte
		// 00 01 Mifare 1K
		// 00 02 Mifare 4K
		// 00 03 Mifare Ultralight
		
		if( atr[13] == (byte)0x00 && atr[14] == (byte)0x01 ){
			card = new Mifare1K();
		}else{
			throw new CardNotSupportedException("Card inserted is not supported!");
		}
		
		return card;
	}
	
	public ReaderTransmitResponse Trasmit(byte[] buffer){
		
		ReaderTransmitResponse response = new ReaderTransmitResponse();
		
		try {
			if( terminal.isCardPresent() == false ){
				response.reponseCode = MifareResponseCodes.MF_NO_READER_FOUND;
				return response;
			}
			
			if( buffer == null ){
				response.reponseCode = MifareResponseCodes.MF_NO_SUPPLIED_BUFFER;
				return response;
			}
			
			if( buffer.length == 0 ){
				response.reponseCode = MifareResponseCodes.MF_NO_SUPPLIED_BUFFER;
				return response;
			}
			
			CommandAPDU apduSend=new CommandAPDU(buffer);
			
			ResponseAPDU  responseSend = card.getBasicChannel().transmit(apduSend);
			
			response.reponseCode = MifareResponseCodes.MF_SUCCESS;
			response.reponseAPDU = responseSend;
			
		} catch (CardException e1) {
			response.reponseCode = MifareResponseCodes.MF_CARD_EXCEPTION_ERROR;
			return response;
		}
		
		return response;
	}
}
