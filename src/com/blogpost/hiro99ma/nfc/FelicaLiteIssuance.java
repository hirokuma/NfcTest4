package com.blogpost.hiro99ma.nfc;

import java.io.IOException;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESedeKeySpec;
import javax.crypto.spec.IvParameterSpec;


import android.util.Log;

public final class FelicaLiteIssuance {

	///////////////////////////
	// public fields
	///////////////////////////

	public enum Result {
		SUCCESS,

		ENOTCARD,				///!< カードが見つからない
		EBADSYSCODE,			///!< システムコード不正
		EISSUED,				///!< 発行済み(1次、2次)
		ERROR,					///!< よくわからないがエラー
	}


	///////////////////////////
	// private fields
	///////////////////////////

	private static final String TAG = "FelicaLiteIssuance";


	///////////////////////////
	// methods
	///////////////////////////

	/**
	 * １次発行(システムブロックの書き換え禁止設定は行わない)<br>
	 * <br>
	 * {@link FelicaLite#connect()}を呼び出しておくこと。
	 *
	 * @param dfd			[in]DFD
	 * @param masterKey	[in]個別化マスター鍵(24byte)
	 * @param keyVersion	[in]鍵バージョン
	 * @return			true	１次発行成功
	 * @throws IOException 
	 */
	public static Result issuance1(short dfd, byte[] masterKey, short keyVersion) throws IOException {

		if(FelicaLite.check() != true) {
			Log.e(TAG, "no FelicaLite.connect()");
			return Result.ERROR;
		}

		// 7.3.1 Pollingレスポンスの確認
		boolean ret = FelicaLite.polling(FelicaLite.SC_BROADCAST);
		if(!ret) {
			Log.e(TAG, "card not found.");
			return Result.ENOTCARD;
		}

		// 7.3.2 システムコードの確認
		ret = checkSystemCode();
		if(!ret) {
			Log.e(TAG, "bad system code.");
			return Result.EBADSYSCODE;
		}

		// 発行済みチェック
		ret = checkNotIssuance();
		if(!ret) {
			Log.e(TAG, "issuanced card.");
			return Result.EISSUED;
		}

		// 7.3.3 IDの設定
		ret = writeID(dfd);
		if(!ret) {
			Log.e(TAG, "write ID fail.");
			return Result.ERROR;
		}

		// 7.3.4 カード鍵の書き込み
		// 7.3.5 カード鍵の確認
		ret = writeCardKey(masterKey);
		if(!ret) {
			Log.e(TAG, "write Card Key fail.");
			return Result.ERROR;
		}

		// 7.3.6 カード鍵バージョンの書き込み
		ret = writeKeyVersion(keyVersion);
		if(!ret) {
			Log.e(TAG, "write Key Version fail.");
			return Result.ERROR;
		}

		// 7.3.7 ユーザーブロックの書き込み
		//やらない

		// 7.3.8 システムブロックの書き換え禁止設定
		//これを行うと元に戻れなくなるので、コメントアウトしておく
//		ret = writeIssuance1();
//		if(!ret) {
//			Log.e(TAG, "write Issuance sign fail.");
//			return Result.ERROR;
//		}


		return Result.SUCCESS;
	}

	
	/**
	 * MAC比較<br>
	 * <br>
	 * {@link FelicaLite#connect()}を呼び出しておくこと。<br>
	 *
	 * @param masterKey	[in]個別化マスター鍵(24byte)
	 * @return		true	MAC一致
	 * @throws IOException 
	 */
	public static boolean macCheck(byte[] masterKey) throws IOException {
		return macCheckInternal(masterKey, null);
	}


	/**
	 * システムブロックの書き換え禁止(不可逆なので要注意)<br>
	 * <br>
	 * 処理が成功した場合、MC_ALLレジスタは書き込み可能に戻すことができなくなる。<br>
	 * 本当に呼び出してよいかどうかは、FeliCa Liteユーザーズマニュアルを確認すること。<br>
	 * 少なくとも、NFCの実験目的でやっているような場合は、呼び出す必要はない。<br>
	 * <br>
	 * {@link FelicaLite#connect()}を呼び出しておくこと。<br>
	 * 
	 * @return		true:書き換え禁止成功
	 * @throws IOException
	 * @attention	実行すると、システム領域の一部が書込禁止になり、元に戻すことはできない
	 */
	public static boolean writeIssuance1() throws IOException {
		byte[] buf = FelicaLite.readBlock(FelicaLite.MC);
		if(buf == null) {
			Log.v(TAG, "writeIssuance1 : read fail");
			return false;
		}
		
		// 7.3.8 システムブロックの書き換え禁止設定(不可逆)
		buf[2] = 0x00;		//MC_ALL
		boolean ret = FelicaLite.writeBlock(FelicaLite.MC, buf);
		if(ret == false) {
			Log.v(TAG, "writeIssuance1 : write fail");
			return false;
		}
		return ret;
	}
	

	/**
	 * システムコード確認<br>
	 *
	 * @return	true	FeliCa Liteである
	 * @throws IOException 
	 */
	private static boolean checkSystemCode() throws IOException {
		byte[] buf = FelicaLite.readBlock(FelicaLite.SYS_C);
		if(buf == null) {
			Log.v(TAG, "checkSystemCode : read fail");
			return false;
		}
		int sc = (int)((((int)buf[0] << 8) & 0xff00) | ((int)buf[1] & 0xff));
		if(sc != FelicaLite.SC_FELICALITE) {
			Log.v(TAG, "checkSystemCode : invalid syscode");
			return false;
		}
		for(int i=2; i<FelicaLite.SIZE_BLOCK; i++) {
			if(buf[i] != 0x00) {
				Log.v(TAG, "checkSystemCode : invalid block");
				return false;
			}
		}

		return true;
	}

	
	/**
	 * 未発行確認<br>
	 * <br>
	 * - MCレジスタ3バイト目(MC_ALL)が0x00なら、1次発行済み<br>
	 * - MCレジスタ2バイト目(MC_SP[1])のb7が0なら、2次発行済み<br>
	 *
	 * @return		true	未発行である
	 * @throws IOException 
	 */
	private static boolean checkNotIssuance() throws IOException {
		byte[] buf = FelicaLite.readBlock(FelicaLite.MC);
		if(buf == null) {
			Log.v(TAG, "checkNotIssuance : read fail");
			return false;
		}
		if(buf[2] == 0x00) {
			Log.v(TAG, "checkNotIssuance : first issuranced");
			return false;
		}
		if((buf[1] & 0x80) == 0) {
			Log.v(TAG, "checkNotIssuance : second issuranced");
			return false;
		}
		return true;
	}

	/**
	 * IDの設定<br>
	 * 0～7   : D_IDの前半8byte<br>
	 * 8～9   : DFD<br>
	 * 10～15 : 任意<br>
	 * 
	 * @param	dfd		[in]DFD
	 * @return	true	書込成功
	 * @throws IOException 
	 *
	 */
	private static boolean writeID(short dfd) throws IOException {
		byte[] buf = FelicaLite.readBlock(FelicaLite.D_ID);
		if(buf == null) {
			Log.v(TAG, "writeID : read fail");
			return false;
		}

		//DFD
		buf[8] = (byte)((dfd & 0xff00) >> 8);
		buf[9] = (byte)(dfd & 0xff);
		
		//any value
		buf[10] = 'h';
		buf[11] = 'i';
		buf[12] = 'r';
		buf[13] = 'o';
		buf[14] = '9';
		buf[15] = '9';
		boolean ret = writeWithCheck(buf, FelicaLite.ID);
		if(ret == false) {
			Log.v(TAG, "writeID : write fail");
			return false;
		}

		return true;
	}
	

	/**
	 * カード鍵の書き込み.<br>
	 * <br>
	 * 24byteの個別化マスター鍵と16byteのIDブロックから個別化カード鍵を作成し、書き込む。<br>
	 *
	 * @param masterKey	[in]個別化マスター鍵(24byte)
	 * @return
	 * @throws IOException 
	 */
	private static boolean writeCardKey(byte[] masterKey) throws IOException {
		byte[] id = FelicaLite.readBlock(FelicaLite.ID);
		if(id == null) {
			Log.v(TAG, "writeCardKey: read ID fail");
			return false;
		}
		byte[] ck = new byte[FelicaLite.SIZE_BLOCK];
		boolean ret = calcPersonalCardKey(ck, masterKey, id);
		if(ret == false) {
			Log.v(TAG, "writeCardKey: personal key fail");
			return false;
		}

		//CKはチェックできない
		ret = FelicaLite.writeBlock(FelicaLite.CK, ck);
		if(ret == false) {
			Log.v(TAG, "writeCardKey : write fail");
			return false;
		}

		ret = macCheckInternal(null, ck);
		if(ret == false) {
			Log.v(TAG, "writeCardKey : mac fail");
			return false;
		}

		return true;
	}


	/**
	 * MAC比較<br>
	 * <br>
	 * RCにランダム値を書き込んだ後、IDブロックとMACブロックを2ブロック同時に読み込む。<br>
	 * そのときのMACと、RCと個別化マスター鍵で計算したMACを比較する。<br>
	 *
	 * @param masterKey	[in]個別化マスター鍵(24byte)
	 * @param ck			[in]カード鍵。nullの場合、masterKeyから計算する。
	 * @return		true	MAC一致
	 * @throws IOException 
	 */
	private static boolean macCheckInternal(byte[] masterKey, byte[] ck) throws IOException {
		//カードのMAC(IDブロック)→buf[0-15]にIDが、buf[16-31]にMACが入る
		byte[] rc = new byte[FelicaLite.SIZE_BLOCK];			//ランダム値を入れる
		SecureRandom random = new SecureRandom();
		random.nextBytes(rc);
		boolean ret = FelicaLite.writeBlock(FelicaLite.RC, rc);
		if(ret == false) {
			Log.v(TAG, "macCheck : write rc fail");
			return false;
		}
		int[] blkNo = new int[] { FelicaLite.ID, FelicaLite.MAC };
		byte[] buf = FelicaLite.readBlock(blkNo);
		if(buf == null) {
			Log.v(TAG, "macCheck : read fail");
			return false;
		}

		//個別化カード鍵の計算→ck
		if(ck == null) {
			ck = new byte[16];
			ret = calcPersonalCardKey(ck, masterKey, buf);
			if(ret == false) {
				Log.v(TAG, "macCheck: personal key fail");
				return false;
			}
		}

		// MACの計算(bufはID)
		byte[] mac = new byte[8];
		ret = calcMac(mac, ck, buf, rc);
		if(ret == false) {
			Log.v(TAG, "macCheck: mac calc fail");
			return false;
		}
		
		//比較
		for(int i=0; i<8; i++) {
			if(buf[16+i] != mac[i]) {
				Log.v(TAG, "macCheck: mac not match fail");
				return false;
			}
		}

		return ret;
	}


	/**
	 * 鍵バージョン書き込み<br>
	 *
	 * @param keyVersion	[in]鍵バージョン
	 * @return		true	書き込み成功
	 * @throws IOException 
	 */
	private static boolean writeKeyVersion(short keyVersion) throws IOException {
		byte[] buf = new byte[FelicaLite.SIZE_BLOCK];
		buf[0] = (byte)((keyVersion & 0xff00) >> 8);
		buf[1] = (byte)(keyVersion & 0xff);
		boolean ret = writeWithCheck(buf, FelicaLite.CKV);
		if(ret == false) {
			Log.v(TAG, "writeKeyVersion : write fail");
			return false;
		}

		return true;
	}
	
	
	/**
	 * チェック付きブロック書き込み(16byte)<br>
	 *
	 * @param buf		[in]書き込みデータ
	 * @param blockNo	[in]書き込みブロック番号
	 * @return	true	チェックOK
	 * @throws IOException 
	 */
	private static boolean writeWithCheck(byte[] buf, int blk) throws IOException {
		boolean ret = FelicaLite.writeBlock(blk, buf);
		if(ret == false) {
			Log.v(TAG, "checkWrite : write fail");
			return false;
		}

		byte[] bufChk = FelicaLite.readBlock(blk);
		if(bufChk == null) {
			Log.v(TAG, "checkWrite : read fail");
			return false;
		}
		for(int i=0; i<FelicaLite.SIZE_BLOCK; i++) {
			if(buf[i] != bufChk[i]) {
				Log.v(TAG, "checkWrite : bad read result");
				return false;
			}
		}

		return true;
	}

	
	/**
	 * MAC計算<br>
	 * <br>
	 * 8byteごとにエンディアンをひっくり返す<br>
	 *
	 * @param mac	[out]MAC計算結果(先頭から8byte書く)。エラーになっても書き換える可能性あり。
	 * @param ck	[in]カード鍵(16byte)
	 * @param id	[in]ID(16byte)
	 * @param rc	[in]ランダムチャレンジブロック(16byte)
	 * @return		true	MAC計算成功
	 */
	private static boolean calcMac(byte[] mac, byte[] ck, byte[] id, byte[] rc) {
		byte[] sk = new byte[16];
		IvParameterSpec ips = null;

		// 秘密鍵を準備([0-7]CK1, [8-15]CK2, [16-23]CK1
		byte[] key = new byte[24];
		for(int i=0; i<8; i++) {
			key[i] = key[16+i] = ck[7-i];
			key[8+i] = ck[15-i];
		}

		byte[] rc1 = new byte[8];
		byte[] rc2 = new byte[8];
		byte[] id1 = new byte[8];
		byte[] id2 = new byte[8];
		for(int i=0; i<8; i++) {
			rc1[i] = rc[7-i];
			rc2[i] = rc[15-i];
			id1[i] = id[7-i];
			id2[i] = id[15-i];
		}

		// RC[1]==(CK)==>SK[1]
		ips = new IvParameterSpec(new byte[8]);		//zero
		int ret = enc83(sk, 0, key, rc1, 0, ips);		//RC1-->SK1
		if(ret != 8) {
			Log.e(TAG, "calcMac: proc1");
			return false;
		}

		// SK[1] =(iv)> RC[2] =(CK)=> SK[2]
		ips = new IvParameterSpec(sk, 0, 8);	//SK1
		ret = enc83(sk, 8, key, rc2, 0, ips);	//RC2-->SK2
		if(ret != 8) {
			Log.e(TAG, "calcMac: proc2");
			return false;
		}

		/////////////////////////////////////////////////////////

		//SKは既にエンディアンがひっくり返っている(はず)
		for(int i=0; i<8; i++) {
			key[i] = key[16+i] = sk[i];
			key[8+i] = sk[8+i];
		}

		// RC[1] =(iv)=> ID[1] =(SK)=> tmp
		ips = new IvParameterSpec(rc1, 0, 8);	//RC1
		ret = enc83(mac, 0, key, id1, 0, ips);	//ID1-->tmp
		if(ret != 8) {
			Log.e(TAG, "calcMac: proc3");
			return false;
		}

		// tmp =(iv)=> ID[2] =(SK)=> tmp
		ips = new IvParameterSpec(mac);			//tmp
		ret = enc83(mac, 0, key, id2, 0, ips);	//ID1-->tmp
		if(ret != 8) {
			Log.e(TAG, "calcMac: proc4");
			return false;
		}

		for(int i=0; i<4; i++) {
			byte swp = mac[i];
			mac[i] = mac[7-i];
			mac[7-i] = swp;
		}

		return true;
	}


	/**
	 * 個別化カード鍵作成
	 *
	 * @param personalKey	[out]生成した個別化カード鍵(16byte)
	 * @param masterKey	[in]個別化マスター鍵K(24byte)
	 * @param id			[in]IDブロックM(16byte)
	 * @return		true	作成成功
	 */
	static private boolean calcPersonalCardKey(byte[] personalKey, byte[] masterKey, byte[] id) {
		IvParameterSpec ips = new IvParameterSpec(new byte[8]);

		//2. 8byte分の0x00を平文、Kを鍵として3DES→結果L
		byte[] enc1 = new byte[8];		//L
		byte[] text = new byte[8];
		int ret = enc83(enc1, 0, masterKey, text, 0, ips);
		if(ret != 8) {
			Log.e(TAG, "calcPersonalCardKey: proc1");
			return false;
		}

		//3. L → K1
		//	Lの最上位ビットが0 → Lの全体を左1ビットするのみ
		//	Lの最上位ビットが1 → Lの全体を左1ビットした後、最下位バイトを0x1Bとxorする
		boolean msb = false;
		for(int i=7; i>=0; i--) {
			boolean bak = msb;
			msb = ((enc1[i] & 0x80) != 0) ? true : false;
			enc1[i] <<= 1;
			if(bak) {
				//下のバイトからのcarry
				enc1[i] |= 0x01;
			}
		}
		if(msb) {
			enc1[7] ^= 0x1b;
		}

		//4. Mを先頭から8byteずつに分け、M1, M2*とする
		//5. M2* xor K1 → M2
		//
		//注意：「FeliCa Liteに関するソフトウェア開発テクニカルノート」
		//			1.7. DES演算の入出力データの並び(エンディアン)について
		//		これによると、FeliCa Liteの場合、DES演算するときはデータ8byteを
		//		並べ替えて演算の入力とし、その結果をまた並び替えて出力しているとのこと。
		byte[] id1 = new byte[8];		//M1
		byte[] id2 = new byte[8];		//M2
		for(int i=0; i<8; i++) {
			//エンディアンを変更しつつM1とM2に分割
			id1[i] = id[7-i];
			id2[i] = (byte)(id[15-i] ^ enc1[i]);
		}

		//6. M1を平文、Kを鍵として3DES→結果C1
		byte[] c1 = new byte[8];
		ret = enc83(c1, 0, masterKey, id1, 0, ips);	//c1
		if(ret != 8) {
			Log.e(TAG, "calcPersonalCardKey: proc2");
			return false;
		}

		//7. (C1 xor M2)を平文、Kを鍵として3DES→結果T
		ips = new IvParameterSpec(c1);
		byte[] t = new byte[8];
		ret = enc83(t, 0, masterKey, id2, 0, ips);	//t
		if(ret != 8) {
			Log.e(TAG, "calcPersonalCardKey: proc3");
			return false;
		}

		//8. M1の最上位ビットを反転→M1'
		id1[0] ^= 0x80;		//M1'
		
		//9. M1'を平文、Kを鍵として3DES→結果C1'
		ips = new IvParameterSpec(new byte[8]);
		ret = enc83(c1, 0, masterKey, id1, 0, ips);	//c1'
		if(ret != 8) {
			Log.e(TAG, "calcPersonalCardKey: proc4");
			return false;
		}

		//10. (C1' xor M2)を平文、Kを鍵として3DES→結果T'
		ips = new IvParameterSpec(c1);	//c1'
		ret = enc83(c1, 0, masterKey, id2, 0, ips);	//t'
		if(ret != 8) {
			Log.e(TAG, "calcPersonalCardKey: proc5");
			return false;
		}

		//11. Tを上位8byte、T'を下位8byte→結果C→個別化カード鍵
		for(int i=0; i<8; i++) {
			personalKey[i] = t[i];
			personalKey[8+i] = c1[i];
		}

		return true;
	}


	/**
	 * Triple-DES暗号化<br>
	 * <br>
	 * CBC(Cipher Block Chaining)を使うため、初期ベクタが必要。<br>
	 * というよりも、「AとBとの排他的論理和を平文とし」の処理を自動でやってくれるのでCBCにした。<br>
	 * すなわち「(inBuf xor ips)を平文とし、keyを鍵としてトリプルDES暗号化」する。<br>
	 *
	 * @param outBuf		[out]暗号化出力バッファ(8byte以上)
	 * @param outOffset	[in]暗号化出力バッファへの書き込み開始位置(ここから8byte書く)
	 * @param key			[in]秘密鍵(24byte [0-7]KEY1, [8-15]KEY2, [16-23]KEY3)
	 * @param inBuf		[in]平文バッファ(8byte以上)
	 * @param inOffset		[in]平文バッファの読み込み開始位置(ここから8byte読む)
	 * @param ips			[in]初期ベクタ(8byte)
	 * @return		true	暗号化成功
	 */
	private static int enc83(byte[] outBuf, int outOffset, byte[] key, byte[] inBuf, int inOffset, IvParameterSpec ips) {
		int sz = 0;
		try {
			// 秘密鍵を準備
			SecretKeyFactory skf = SecretKeyFactory.getInstance("DESede");	//3DES
			SecretKey sk = skf.generateSecret(new DESedeKeySpec(key));

			// 暗号
			Cipher ci = Cipher.getInstance("DESede/CBC/NoPadding");		//3DES / Cipher Block Chaining / パディング無し
			ci.init(Cipher.ENCRYPT_MODE, sk, ips);
			sz = ci.doFinal(inBuf, inOffset, 8, outBuf, outOffset);

		} catch (Exception e) {
			Log.e(TAG, "enc83 exception");
		}

		return sz;
	}
}
