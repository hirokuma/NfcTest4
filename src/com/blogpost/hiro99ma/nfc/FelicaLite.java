package com.blogpost.hiro99ma.nfc;

import java.io.IOException;

import android.nfc.Tag;
import android.nfc.tech.NfcF;


/**
 * @class	FelicaLite
 * @brief	FeliCa Lite card access
 */
public class FelicaLite {
	private static Tag mTag;
	private static NfcF mNfcF;

	/**
	 * 使用する場合、最初に呼び出す。
	 * 内部で{@link NfcF#connect()}を呼び出す。
	 * 呼び出し場合、最後に{@link FelicaLite#close()}を呼び出すこと。
	 * 
	 * @param[in]	tag		intentで取得したTag
	 * @return		NfcF
	 * @throws IOException
	 *  
	 * @sa			{@link FelicaLite#close()}
	 */
	public static NfcF connect(Tag tag) throws IOException {
		mTag = tag;
		mNfcF = NfcF.get(tag);
		mNfcF.connect();
		return mNfcF;
	}
	
	
	/**
	 * {@link FelicaLite#connect()}を呼び出したら、最後に呼び出すこと。
	 * 内部で{@link NfcF#close()}を呼び出す。
	 * 
	 * @throws IOException
	 * 
	 * @sa		{@link FelicaLite#connect(Tag)}
	 */
	public static void close() throws IOException {
		mNfcF.close();
		mTag = null;
		mNfcF = null;
	}
	

	/**
	 * 1ブロック書込み
	 * 
	 * @param[in] blockNo		書込対象のブロック番号
	 * @param[in] data			書き込みデータ(先頭の16byteを使用)
	 * @return		true:書込成功
	 * @throws IOException
	 */
	public static boolean writeBlock(int blockNo, byte[] data) throws IOException {
		if((data == null) || (data.length < 16)) {
			//データ不正
			return false;
		}
		
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
		if((ret[1] != 0x09) || (ret[10] != 0x00) || (ret[11] != 0x00)) {
			ret = null;
			return false;
		}
		ret = null;
		return true;
	}
	
	
	/**
	 * 1ブロック読み込み
	 * 
	 * @param[in] blockNo		読込対象のブロック番号
	 * @return					(!=null)読み込んだ1ブロックデータ / (==null)エラー
	 * @throws IOException
	 */
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
		if((ret[1] != 0x07) || (ret[10] != 0x00) || (ret[11] != 0x00)) {
			ret = null;
			return null;
		}
		
		//read data copy
		System.arraycopy(ret, 13, buf, 0, 16);
		ret = null;
		return buf;
	}
}
