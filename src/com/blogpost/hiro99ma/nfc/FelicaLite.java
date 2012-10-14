package com.blogpost.hiro99ma.nfc;

import java.io.IOException;

import android.nfc.Tag;
import android.nfc.tech.NfcF;
import android.util.Log;


/**
 * @class	FelicaLite
 * @brief	FeliCa Lite card access
 */
public class FelicaLite {
	public static final int SC_BROADCAST = 0xffff;
	public static final int SC_FELICALITE = 0x88b4;
	public static final int SC_NFCF = 0x12fc;

	public static final int PAD0 = 0x0000;
	public static final int PAD1 = 0x0001;
	public static final int PAD2 = 0x0002;
	public static final int PAD3 = 0x0003;
	public static final int PAD4 = 0x0004;
	public static final int PAD5 = 0x0005;
	public static final int PAD6 = 0x0006;
	public static final int PAD7 = 0x0007;
	public static final int PAD8 = 0x0008;
	public static final int PAD9 = 0x0009;
	public static final int PAD10 = 0x000a;
	public static final int PAD11 = 0x000b;
	public static final int PAD12 = 0x000c;
	public static final int PAD13 = 0x000d;
	public static final int REG = 0x000e;
	public static final int RC = 0x0080;
	public static final int MAC = 0x0081;
	public static final int ID = 0x0082;
	public static final int D_ID = 0x0083;
	public static final int SER_C = 0x0084;
	public static final int SYS_C = 0x0085;
	public static final int CKV = 0x0086;
	public static final int CK = 0x0087;
	public static final int MC = 0x0088;
	
	public static final int SIZE_BLOCK = 16;

	private static final String TAG = "FelicaLite";
	private static Tag mTag;
	private static NfcF mNfcF;

	/**
	 * 使用する場合、最初に呼び出す。
	 * 内部で{@link NfcF#connect()}を呼び出す。
	 * 呼び出し場合、最後に{@link FelicaLite#close()}を呼び出すこと。
	 * 
	 * {@link FelicaLite#close()}が呼ばれるまでtagをキャッシュする。
	 *
	 * @param[in]	tag		intentで取得したTag
	 * @return		NfcF
	 * @throws IOException
	 * @see		{@link FelicaLite#close()}
	 */
	public static NfcF connect(Tag tag) throws IOException {
		mTag = tag;
		mNfcF = NfcF.get(tag);
		mNfcF.connect();
		return mNfcF;
	}

	
	/**
	 * {@link #connect(Tag)}を呼び出したかどうかのチェック
	 * 
	 * @return	true	呼び出している
	 */
	static boolean check() {
		return (mTag != null) && (mNfcF != null);
	}
	

	/**
	 * {@link FelicaLite#connect()}を呼び出したら、最後に呼び出すこと。
	 * 内部で{@link NfcF#close()}を呼び出す。
	 *
	 * @throws IOException
	 * @see		{@link FelicaLite#connect(Tag)}
	 * @note	- {@link FelicaLite#connect(Tag)}でキャッシュしたtagを解放する
	 */
	public static void close() throws IOException {
		mNfcF.close();
		mTag = null;
		mNfcF = null;
	}


	/**
	 * ポーリング
	 * 
	 * {@link FelicaLite#connect()}を呼び出しておくこと。
	 *
	 * @param sc			[in]サービスコード
	 * @return				true	ポーリング成功
	 * @throws IOException
	 */
	public static boolean polling(int sc) throws IOException {
		byte[] buf = new byte[6];
		buf[0] = 6;
		buf[1] = 0x00;
		buf[2] = (byte)((sc & 0xff00) >> 8);
		buf[3] = (byte)(sc & 0xff);
		buf[4] = 0x00;
		buf[5] = 0x00;

		byte[] ret = mNfcF.transceive(buf);

		//length check
		if(ret.length != 18) {
			Log.e(TAG, "polling : length");
			return false;
		}
		//IDm check
		byte[] idm = mTag.getId();
		for(int i=0; i<8; i++) {
			if(ret[i+2] != idm[i]) {
				Log.e(TAG, "polling : nfcid");
				return false;
			}
		}
		//response code check
		if(ret[1] != 0x01) {
			Log.e(TAG, "polling : response code");
			return false;
		}

		return true;
	}


	/**
	 * 1ブロック書込み
	 * 
	 * {@link FelicaLite#connect()}を呼び出しておくこと。
	 *
	 * @param blockNo		[in]書込対象のブロック番号
	 * @param data			[in]書き込みデータ(先頭の16byteを使用)
	 * @return		true	書込成功
	 * @throws IOException
	 */
	public static boolean writeBlock(int blockNo, byte[] data) throws IOException {
		if((data == null) || (data.length < 16)) {
			//データ不正
			Log.e(TAG, "writeBlock : param");
			return false;
		}

		byte[] buf = new byte[32];
		buf[0] = 32;					//length
		buf[1] = (byte)0x08;			//Write Without Encryption
		System.arraycopy(mTag.getId(), 0, buf, 2, 8);
		buf[10] = (byte)0x01;			//service num
		buf[11] = (byte)0x09;			//service code list(lower)
		buf[12] = (byte)0x00;			//service code list(upper)
		buf[13] = (byte)0x01;			//blocklist num
		buf[14] = (byte)0x80;			//2byte-blocklist(upper)
		buf[15] = (byte)blockNo;		//2byte-blocklist(lower)
		System.arraycopy(data, 0, buf, 16, SIZE_BLOCK);

		byte[] ret = mNfcF.transceive(buf);

		//length check
		if(ret.length != 12) {
			Log.e(TAG, "writeBlock : length");
			return false;
		}
		//IDm check
		for(int i=2+0; i<2+8; i++) {
			if(ret[i] != buf[i]) {
				Log.e(TAG, "writeBlock : nfcid");
				return false;
			}
		}
		//status flag check
		if((ret[1] != 0x09) || (ret[10] != 0x00) || (ret[11] != 0x00)) {
			Log.e(TAG, "writeBlock : status");
			return false;
		}
		return true;
	}


	/**
	 * 1ブロック読み込み<br>
	 * <br>
	 * {@link FelicaLite#connect()}を呼び出しておくこと。
	 *
	 * @param blockNo		[in]読込対象のブロック番号
	 * @return				(!=null)読み込んだ1ブロックデータ / (==null)エラー
	 * @throws IOException
	 */
	public static byte[] readBlock(int blockNo) throws IOException {
		byte[] buf = new byte[16];
		buf[0] = 16;					//length
		buf[1] = (byte)0x06;			//Read Without Encryption
		System.arraycopy(mTag.getId(), 0, buf, 2, 8);
		buf[10] = (byte)0x01;			//service num
		buf[11] = (byte)0x0b;			//service code list(lower)
		buf[12] = (byte)0x00;			//service code list(upper)
		buf[13] = (byte)0x01;			//blocklist num
		buf[14] = (byte)0x80;			//2byte-blocklist(upper)
		buf[15] = (byte)blockNo;		//2byte-blocklist(lower)

		byte[] ret = mNfcF.transceive(buf);

		//length check
		if(ret.length != 29) {
			Log.e(TAG, "readBlock : length");
			return null;
		}
		//IDm check
		for(int i=2+0; i<2+8; i++) {
			if(ret[i] != buf[i]) {
				Log.e(TAG, "readBlock : nfcid");
				return null;
			}
		}
		//status flag check
		if((ret[1] != 0x07) || (ret[10] != 0x00) || (ret[11] != 0x00)) {
			Log.e(TAG, "readBlock : status");
			return null;
		}

		//read data copy
		//(buf.lengthが16なので、使い回ししている)
		System.arraycopy(ret, 13, buf, 0, SIZE_BLOCK);
		return buf;
	}

	/**
	 * nブロック読み込み<br>
	 * <br>
	 * - {@link FelicaLite#connect()}を呼び出しておくこと。<br>
	 * - blockNo.lengthが4より大きい場合、先頭の4つを使用する。<br>
	 *
	 * @param blockNo		[in]読込対象のブロック番号(4つまで)
	 * @return				(!=null)読み込んだブロックデータ(blockNoの順) / (==null)エラー
	 * @throws IOException
	 */
	public static byte[] readBlock(int[] blockNo) throws IOException {
		int num = blockNo.length;
		if(num > 4) {
			//FeliCa Lite limit
			Log.w(TAG, "readBlocks : 4blocks limit");
			num = 4;
		}
		byte[] buf = new byte[14 + num * 2];
		buf[0] = (byte)(14 + num * 2);	//length
		buf[1] = (byte)0x06;			//Read Without Encryption
		System.arraycopy(mTag.getId(), 0, buf, 2, 8);
		buf[10] = (byte)0x01;			//service num
		buf[11] = (byte)0x0b;			//service code list(lower)
		buf[12] = (byte)0x00;			//service code list(upper)
		buf[13] = (byte)num;			//blocklist num
		for(int loop=0; loop<num; loop++) {
			buf[14 + loop * 2]     = (byte)0x80;			//2byte-blocklist(upper)
			buf[14 + loop * 2 + 1] = (byte)blockNo[loop];	//2byte-blocklist(lower)
		}

		byte[] ret = mNfcF.transceive(buf);

		//length check
		if(ret.length != 13 + num * SIZE_BLOCK) {
			Log.e(TAG, "readBlocks : length");
			return null;
		}
		//IDm check
		for(int i=2+0; i<2+8; i++) {
			if(ret[i] != buf[i]) {
				Log.e(TAG, "readBlocks : nfcid");
				return null;
			}
		}
		//status flag check
		if((ret[1] != 0x07) || (ret[10] != 0x00) || (ret[11] != 0x00) || (ret[12] != num)) {
			Log.e(TAG, "readBlocks : status");
			return null;
		}

		//read data copy
		byte[] res = new byte[num * SIZE_BLOCK];
		System.arraycopy(ret, 13, res, 0, num * SIZE_BLOCK);
		return res;
	}
}
