package com.detorresrc.main;

public class Util {
	public static String bytesToChar(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (int i = 0; i < bytes.length; i++) {
            sb.append(String.format("%c", bytes[i]));
        }

        return sb.toString();
    }
	
	public static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (int i = 0; i < bytes.length; i++) {
            sb.append(String.format("%02x ", bytes[i]));
        }

        return sb.toString();
    }
	
	public static boolean ArrayByteCompare(byte[] a, byte[] b){
		boolean ret = true;
		
		if( a.length == b.length ){
			for( int i=0; i<a.length; i++ ){
				if( a[i] != b[i] ){
					ret = false;
					break;
				}
			}
		}else{
			ret = false;
		}
		
		return ret;
	}
}
