package com.blogpost.hiro99ma.nfc;

import java.io.IOException;

import android.nfc.NfcAdapter;
import android.nfc.Tag;
import android.nfc.tech.NfcF;
import android.os.Bundle;
import android.app.Activity;
import android.app.PendingIntent;
import android.content.Intent;
import android.content.IntentFilter;
import android.view.Menu;
import android.view.View;
import android.widget.TextView;
import android.widget.Toast;

public class MainActivity extends Activity {
	private NfcAdapter mAdapter;
	private PendingIntent mPendingIntent;
	private IntentFilter[] mFilters;
	private String[][] mTechLists;
	private Tag mTag;

    @Override
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);


		// NFC
		mAdapter = NfcAdapter.getDefaultAdapter(this);
		mPendingIntent = PendingIntent.getActivity(this, 0, new Intent(this, getClass()).addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP), 0);

		IntentFilter tech = new IntentFilter(NfcAdapter.ACTION_TECH_DISCOVERED);
		mFilters = new IntentFilter[] { tech };

		mTechLists = new String[][] {
						new String[] { NfcF.class.getName() }
		};
    }

    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        getMenuInflater().inflate(R.menu.activity_main, menu);
        return true;
    }

	@Override
	public void onResume() {
		super.onResume();
		if (mAdapter != null) {
			mAdapter.enableForegroundDispatch(this, mPendingIntent, mFilters, mTechLists);
		}
	}

	@Override
	public void onPause() {
		super.onPause();
		if (mAdapter != null) {
			mAdapter.disableForegroundDispatch(this);
		}
	}

	@Override
	public void onNewIntent(Intent intent) {
		mTag = intent.getParcelableExtra(NfcAdapter.EXTRA_TAG);
	}

	public void onClickRead(View v) {
		if (mTag == null) {
			Toast.makeText(this, "no card", Toast.LENGTH_SHORT).show();
			return;
		}
		try {
			FelicaLite.connect(mTag);
			byte[] rd = FelicaLite.readBlock(0);
			if(rd != null) {
				TextView tv = (TextView)findViewById(R.id.textRead);
				String s = "";
				for(int i=0; i<rd.length; i++) {
					s += String.format("%02x-", rd[i]);
				}
				tv.setText(s);
			}
			FelicaLite.close();
		} catch (IOException e) {
			e.printStackTrace();
		}
	}
}
