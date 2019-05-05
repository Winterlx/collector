package org.newtonproject.newcashcollecter;

import android.app.PendingIntent;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.content.Intent;
import android.nfc.NfcAdapter;
import android.nfc.Tag;
import android.nfc.tech.MifareUltralight;
import android.os.Environment;
import android.os.VibrationEffect;
import android.os.Vibrator;
import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.text.Editable;
import android.text.TextUtils;
import android.text.TextWatcher;
import android.util.Log;
import android.view.KeyEvent;
import android.widget.Button;
import android.widget.RadioButton;
import android.widget.RadioGroup;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;

import org.androidannotations.annotations.Click;
import org.androidannotations.annotations.EActivity;
import org.androidannotations.annotations.ViewById;
import org.androidannotations.annotations.ViewsById;
import org.apache.commons.io.FileUtils;
import org.web3j.utils.Numeric;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;

@EActivity
public class MainActivity extends AppCompatActivity {

    private NfcAdapter mNfcAdapter;
    private PendingIntent mPendingIntent;
    public static File dataFile;

    private static String TAG = "test";
    public static final int PROTOCOL_LENGTH = 100;

    byte[] key = Numeric.hexStringToByteArray("e6272fac54161006186b14da2a54ad49");
    byte[] iv = Numeric.hexStringToByteArray("7662af330791fcc91e719a05598e024b");

    @ViewById
    RadioGroup rg_selGroup;
    @ViewById
    RadioButton rd_1000;
    @ViewById
    RadioButton rd_500;
    @ViewById
    RadioButton rd_200;
    @ViewById
    RadioButton rd_none;
    @ViewById
    TextView tv_contentNumber;
    @ViewById
    TextView tv_content;
    @ViewById
    Button btn_delPrevious;
    @ViewById
    Button btn_copy;
    @ViewById
    ScrollView scrollView;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        Log.e(TAG, "onCreate: ");

        storageFileInit();
    }

    @Override
    public void onNewIntent(Intent intent) {
        Log.e(TAG, "onNewIntent: ");
        readTag(intent);
    }

    @Click
    void btn_copy() {
        ClipboardManager cm = (ClipboardManager) getSystemService(Context.CLIPBOARD_SERVICE);
        ClipData mClipData = ClipData.newPlainText("Label", tv_content.getText());
        cm.setPrimaryClip(mClipData);

        Toast.makeText(this, "已复制到剪贴板。", Toast.LENGTH_SHORT).show();
    }

    @Click
    void btn_delPrevious() {
        String str = tv_content.getText().toString();
        String[] strArray = str.split("\n");
        if (strArray.length == 1) {
            tv_content.setText("");
            writeIntoFile("");
            tv_contentNumber.setText("0");
            return;
        }
        int finalNum = strArray.length - 1;
        StringBuilder newContent = new StringBuilder();
        for (int i = 0; i < finalNum; i++) {
            newContent.append(strArray[i]).append("\n");
        }
        tv_content.setText(newContent);

    }

    private void readTag(Intent intent) {
        Vibrator v = (Vibrator) getSystemService(Context.VIBRATOR_SERVICE);
        assert v != null;
        v.vibrate(VibrationEffect.createOneShot(100, VibrationEffect.DEFAULT_AMPLITUDE));
        String totalData;
        String address = detectOperation(intent);
        if (address == null) {
            Toast.makeText(this, "Address is null!", Toast.LENGTH_SHORT).show();
            return;
        }
        int id = rg_selGroup.getCheckedRadioButtonId();
        switch (id) {
            case R.id.rd_1000:
                totalData = address + ",1000\n";
                break;
            case R.id.rd_500:
                totalData = address + ",500\n";
                break;
            case R.id.rd_200:
                totalData = address + ",200\n";
                break;
            default:
                totalData = address + "\n";
        }
        String content = tv_content.getText() + totalData;
        tv_content.setText(content);
        scrollTextToEnd();
    }

    public String detectOperation(Intent intent) {
        if ("android.nfc.action.TAG_DISCOVERED".equals(intent.getAction()) || "android.nfc.action.NDEF_DISCOVERED".equals(intent.getAction()) || "android.nfc.action.TECH_DISCOVERED".equals(intent.getAction())) {
            Tag detectedTag = intent.getParcelableExtra(NfcAdapter.EXTRA_TAG);
            try {
                byte[] tagText = AES_CTR.DECRYPT(iv,key,readNfcTagWithUltralight(detectedTag));

                return handleData(tagText);
            } catch (Exception e) {
                Log.e(TAG, e.getLocalizedMessage());
                return null;
            }
        } else {
            return null;
        }
    }

    private byte[] readNfcTagWithUltralight(Tag tag) {
        MifareUltralight mifare = MifareUltralight.get(tag);
        try {
            mifare.connect();

            byte[] totalData = new byte[112];
            for (int i = 1; i <= 7; i++) {
                byte[] tmp = mifare.readPages(9 + 4 * i
                );
                System.arraycopy(tmp, 0, totalData, (i - 1) * 16, 16);
            }
            byte[] finalData = new byte[PROTOCOL_LENGTH];
            System.arraycopy(totalData, 2, finalData, 0, PROTOCOL_LENGTH);
            return finalData;
        } catch (Exception ex) {
            Log.e(TAG, "readNfcTagWithUltralight:  " + ex.getLocalizedMessage());
            return null;
        } finally {
            try {
                mifare.close();
            } catch (Exception ex) {
                ex.printStackTrace();
            }
        }
    }

    private String handleData(byte[] tagText) {
        try {
            byte[] data = new byte[PROTOCOL_LENGTH];
            System.arraycopy(tagText, 0, data, 0, PROTOCOL_LENGTH);
            byte[] addressBytes = new byte[20];
            System.arraycopy(data, 0, addressBytes, 0, 20);
            String fromAddress = "0x" + toHexString(addressBytes, 0, addressBytes.length, false);
            return fromAddress;
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }


    public static String toHexString(byte[] input, int offset, int length, boolean withPrefix) {
        StringBuilder stringBuilder = new StringBuilder();
        if (withPrefix) {
            stringBuilder.append("0x");
        }

        for (int i = offset; i < offset + length; ++i) {
            stringBuilder.append(String.format("%02x", input[i] & 255));
        }

        return stringBuilder.toString();
    }

    public static String getInfoFromFile(File file) {
        try {
            return FileUtils.readFileToString(file, "UTF-8");
        } catch (IOException e) {
            e.printStackTrace();
            return null;
        }
    }

    public static void writeIntoFile(String content) {

        byte[] contentByte = content.getBytes();
        try {
            FileOutputStream outStream = new FileOutputStream(dataFile, false);    //文件输出流用于将数据写入文件
            outStream.write(contentByte);
            outStream.close();    //关闭文件输出流
        } catch (Exception e) {
            e.printStackTrace();
        }

    }

    private void storageFileInit() {

        tv_contentNumber.addTextChangedListener(new TextWatcher() {
            @Override
            public void beforeTextChanged(CharSequence s, int start, int count, int after) {

            }

            @Override
            public void onTextChanged(CharSequence s, int start, int before, int count) {

            }

            @Override
            public void afterTextChanged(Editable s) {
                if("0".equals(tv_contentNumber.getText().toString())){
                    btn_delPrevious.setEnabled(false);
                    Log.e(TAG, "afterTextChanged: set false");
                }else {
                    btn_delPrevious.setEnabled(true);
                    Log.e(TAG, "afterTextChanged: set true");
                }
            }
        });

        tv_content.addTextChangedListener(new TextWatcher() {

            @Override
            public void beforeTextChanged(CharSequence s, int start, int count, int after) {

            }

            @Override
            public void onTextChanged(CharSequence s, int start, int before, int count) {
                Log.e(TAG, "onTextChanged: " );
            }

            @Override
            public void afterTextChanged(Editable s) {
                Log.e(TAG, "afterTextChanged: " + s);
                writeIntoFile(s.toString());
                String[] strArray = s.toString().split("\n");
                int num = strArray.length;
                tv_contentNumber.setText(String.valueOf(num));
                Log.e(TAG, "afterTextChanged: " + tv_contentNumber.getText().toString());

            }
        });

        dataFile = new File(getExternalFilesDir(Environment.DIRECTORY_DOCUMENTS) + File.separator + "data.txt");
        if (!dataFile.exists()) {
            try {
                if (dataFile.createNewFile()) {
                    Toast.makeText(this, "Succeed to create data file", Toast.LENGTH_SHORT).show();
                } else {
                    Toast.makeText(this, "failed to create data file", Toast.LENGTH_SHORT).show();
                    Log.e(TAG, "storageFileInit: create failed");
                }
            } catch (IOException e) {
                e.printStackTrace();
            }
        }

        String data = getInfoFromFile(dataFile);
        if (!TextUtils.isEmpty(data)) {
            tv_content.setText(data);
            String[] strArray = data.split("\n");
            int num = strArray.length;
            tv_contentNumber.setText(String.valueOf(num));
        }

    }

    @Override
    protected void onStart() {
        super.onStart();
        mNfcAdapter = NfcAdapter.getDefaultAdapter(this);
        mPendingIntent = PendingIntent.getActivity(this, 0, new Intent(this, getClass()), 0);
    }

    @Override
    public void onResume() {
        super.onResume();
        if (mNfcAdapter != null)
            mNfcAdapter.enableForegroundDispatch(this, mPendingIntent, null, null);
    }

    @Override
    public void onPause() {
        super.onPause();
        if (mNfcAdapter != null)
            mNfcAdapter.disableForegroundDispatch(this);
    }

    private void scrollTextToEnd() {
        scrollView.post(() -> scrollView.fullScroll(ScrollView.FOCUS_DOWN));
    }

}
