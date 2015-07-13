package com.detorresrc.main;

import java.applet.Applet;
import java.security.AccessController;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;
import java.util.List;

import javax.smartcardio.CardException;
import javax.smartcardio.CardTerminal;
import javax.smartcardio.TerminalFactory;

import org.json.JSONObject;

import netscape.javascript.JSObject;

import com.detorresrc.mifare.IMifareCard;
import com.detorresrc.mifare.MifareResponseCodes;
import com.detorresrc.mifare.MifareResponseData;
import com.detorresrc.reader.CardNotSupportedException;
import com.detorresrc.reader.Reader;

public class MifareApplet extends Applet {
	/**
	 * 
	 */
	private static final long serialVersionUID = 104094314808253039L;

	public String ResetCard(){
		String dataRet = null;
		try {
			dataRet = (String) AccessController.doPrivileged(
			  new PrivilegedExceptionAction<String>() {
			    public String run() {
			    	
			    	Reader reader = new Reader();
					
					int ret;
					
					ret = reader.ConnectToReader();
					
					if( ret != MifareResponseCodes.MF_SUCCESS ){
						return "" + ret;
					}
					
					ret = reader.ConnectToCard("T=1");
					if( ret != MifareResponseCodes.MF_SUCCESS ){
						return "" + ret;
					}
					
					IMifareCard card = null;
					try {
						card = reader.GetCard();
						
						ret = card.ResetCard(reader);
						
						if( ret != MifareResponseCodes.MF_SUCCESS ){
							return "" + ret;
						}
						
					} catch (CardNotSupportedException e) {
						return "" + MifareResponseCodes.MF_CARD_NOT_SUPPORTED;
					}
					return "" + MifareResponseCodes.MF_SUCCESS;
			    }
			  }
			);
		} catch (PrivilegedActionException e) {
			dataRet = "999";
		}
		
		return dataRet;
	}
	
	public String InitilizeCard(){
		String dataRet = null;
		try {
			dataRet = (String) AccessController.doPrivileged(
			  new PrivilegedExceptionAction<String>() {
			    public String run() {
			    	
			    	Reader reader = new Reader();
					
					int ret;
					
					ret = reader.ConnectToReader();
					
					if( ret != MifareResponseCodes.MF_SUCCESS ){
						return "" + ret;
					}
					
					ret = reader.ConnectToCard("T=1");
					if( ret != MifareResponseCodes.MF_SUCCESS ){
						return "" + ret;
					}
					
					IMifareCard card = null;
					try {
						card = reader.GetCard();
						
						ret = card.Initialize(reader);
						
						if( ret != MifareResponseCodes.MF_SUCCESS ){
							return "" + ret;
						}
						
					} catch (CardNotSupportedException e) {
						return "" + MifareResponseCodes.MF_CARD_NOT_SUPPORTED;
					}
					return "" + MifareResponseCodes.MF_SUCCESS;
			    }
			  }
			);
		} catch (PrivilegedActionException e) {
			dataRet = "999";
		}
		
		return dataRet;
	}
	
	public String WriteCard(String dataToWrite){
		String dataRet = null;
		try {
			dataRet = (String) AccessController.doPrivileged(
			  new PrivilegedExceptionAction<String>() {
			    public String run() {
			    	
			    	Reader reader = new Reader();
					
					int ret;
					
					ret = reader.ConnectToReader();
					
					if( ret != MifareResponseCodes.MF_SUCCESS ){
						return "" + ret;
					}
					
					ret = reader.ConnectToCard("T=1");
					if( ret != MifareResponseCodes.MF_SUCCESS ){
						return "" + ret;
					}
					
					IMifareCard card = null;
					try {
						card = reader.GetCard();
						
						ret = card.Write(reader, dataToWrite.getBytes());
						
						if( ret != MifareResponseCodes.MF_SUCCESS ){
							return "" + ret;
						}
						
					} catch (CardNotSupportedException e) {
						return "" + MifareResponseCodes.MF_CARD_NOT_SUPPORTED;
					}
					return "" + MifareResponseCodes.MF_SUCCESS;
			    }
			  }
			);
		} catch (PrivilegedActionException e) {
			dataRet = "999";
		}
		
		return dataRet;
	}
	
	public JSONObject ReadCard(){
		JSONObject json = new JSONObject();
	    
		int dataRet;
		try {
			dataRet = (int) AccessController.doPrivileged(
			  new PrivilegedExceptionAction<Integer>() {
			    public Integer run() {
			    	Reader reader = new Reader();
					
					int ret;
					
					ret = reader.ConnectToReader();
					
					if( ret != MifareResponseCodes.MF_SUCCESS ){
						return ret;
					}
					
					ret = reader.ConnectToCard("T=1");
					if( ret != MifareResponseCodes.MF_SUCCESS ){
						return ret;
					}
					
					IMifareCard card = null;
					try {
						card = reader.GetCard();
						
						MifareResponseData responseData = card.Read(reader);
						
						if( responseData.ReturnCode != MifareResponseCodes.MF_SUCCESS ){
							return responseData.ReturnCode;
						}
						
						json.put("data", Util.bytesToChar(responseData.data));
						
					} catch (CardNotSupportedException e) {
						return MifareResponseCodes.MF_CARD_NOT_SUPPORTED;
					}
					return MifareResponseCodes.MF_SUCCESS;
			    }
			  }
			);
		} catch (PrivilegedActionException e) {
			dataRet = 999;
		}
		json.put("code", dataRet);
		return json;
	}
	
	public void CardPresent_Wait(String callback, String secondsToWait){
		JSObject win = JSObject.getWindow(this);
		try {
			AccessController.doPrivileged(
				  new PrivilegedExceptionAction<Void>() {
				    public Void run() {
				    	(new CardPresentListener(win, callback, Integer.parseInt(secondsToWait) )).start();
						return null;
				    }
				  }
			  );
		} catch (PrivilegedActionException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	
	class CardPresentListener extends Thread{
		private JSObject win;
		private String callback;
		private int secondsToWait;
		
		public CardPresentListener(JSObject win, String callback, int secondsToWait){
			this.win = win;
			this.callback = callback;
			this.secondsToWait = secondsToWait;
		}
		
		public void run(){
			TerminalFactory factory = TerminalFactory.getDefault();
			List<CardTerminal> terminals = null;
			try {	
				terminals = factory.terminals().list();
				
				CardTerminal terminal = terminals.get(0);
				
				boolean isCardPresent = terminal.waitForCardPresent((secondsToWait*1000));
				if(isCardPresent==true){
					win.call(this.callback, new Object[] { "" + 0 });
				}else{
					win.call(this.callback, new Object[] { "" + 1 });
				}
				
			} catch (CardException e) {
				win.call(this.callback, new Object[] { "" + 2 });
			}
	    }
	}
}
