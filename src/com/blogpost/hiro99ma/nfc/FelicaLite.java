package com.blogpost.hiro99ma.nfc;

import java.io.IOException;

import android.nfc.Tag;
import android.nfc.tech.NfcF;


public class FelicaLite {
	private static Tag mTag;
	private static NfcF mNfcF;

	public static NfcF connect(Tag tag) throws IOException {
		mTag = tag;
		mNfcF = NfcF.get(tag);
		mNfcF.connect();
		return mNfcF;
	}
	
	public static void close() throws IOException {
		mNfcF.close();
		mTag = null;
		mNfcF = null;
	}
	

	public static boolean writeBlock(int blockNo, byte[] data) throws IOException {
		byte[] buf = new byte[32];
		buf[0] = 32;					//length
		buf[1] = (byte)0x08;			//Write Without Encryption
		System.arraycopy(mTag.getId(), 0, buf, 2, 8);
		buf[10] = (byte)0x01;			//service num
		buf[11] = (byte)0x09;			//service code(lower)
		buf[12] = (byte)0x00;			//service code(upper)
		buf[13] = (byte)0x01;			//blocklist num
		buf[14] = (byte)0x80;			//2byte-blocklist(upper)
		buf[15] = (byte)blockNo;		//2byte-blocklist(lower)
		System.arraycopy(data, 0, buf, 16, 16);

		byte[] ret = mNfcF.transceive(buf);

		//length check
		if(ret.length != 12) {
			ret = null;
			return false;
		}
		//IDm check
		for(int i=2+0; i<2+8; i++) {
			if(ret[i] != buf[i]) {
				ret = null;
				return false;
			}
		}
		//status flag check
		if((ret[10] != 0x00) || (ret[11] != 0x00)) {
			ret = null;
			return false;
		}
		ret = null;
		return true;
	}
	
	public static byte[] readBlock(int blockNo) throws IOException {
		byte[] buf = new byte[16];
		buf[0] = 16;					//length
		buf[1] = (byte)0x06;			//Read Without Encryption 
		System.arraycopy(mTag.getId(), 0, buf, 2, 8);
		buf[10] = (byte)0x01;			//service num
		buf[11] = (byte)0x0b;			//service code(lower)
		buf[12] = (byte)0x00;			//service code(upper)
		buf[13] = (byte)0x01;			//blocklist num
		buf[14] = (byte)0x80;			//2byte-blocklist(upper)
		buf[15] = (byte)blockNo;		//2byte-blocklist(lower)
		
		byte[] ret = mNfcF.transceive(buf);
		
		//length check
		if(ret.length != 29) {
			ret = null;
			return null;
		}
		//IDm check
		for(int i=2+0; i<2+8; i++) {
			if(ret[i] != buf[i]) {
				ret = null;
				return null;
			}
		}
		//status flag check
		if((ret[10] != 0x00) || (ret[11] != 0x00)) {
			ret = null;
			return null;
		}
		
		//read data copy
		System.arraycopy(ret, 13, buf, 0, 16);
		ret = null;
		return buf;
	}
}
