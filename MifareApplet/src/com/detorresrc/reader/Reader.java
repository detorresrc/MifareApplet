package com.detorresrc.reader;

import java.util.List;

import javax.smartcardio.Card;
import javax.smartcardio.CardException;
import javax.smartcardio.CardTerminal;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import javax.smartcardio.TerminalFactory;

import com.detorresrc.mifare.MifareResponseCodes;

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
	
	public int ConnectToCard(String protocol){
		try {
			card = terminal.connect(protocol);
		} catch (CardException e) {
			return MifareResponseCodes.MF_CARD_EXCEPTION_ERROR;
		}

		return MifareResponseCodes.MF_SUCCESS;
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
