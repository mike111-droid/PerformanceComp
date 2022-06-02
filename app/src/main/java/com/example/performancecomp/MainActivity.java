package com.example.performancecomp;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.appcompat.app.AppCompatActivity;

import android.annotation.SuppressLint;
import android.os.Bundle;
import android.os.Debug;
import android.os.Environment;
import android.security.keystore.KeyProperties;
import android.security.keystore.KeyProtection;
import android.util.Base64;
import android.util.Log;
import android.view.View;
import android.widget.Button;
import android.widget.Toast;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.UnrecoverableEntryException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
import java.util.List;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import de.cardcontact.opencard.android.swissbit.SBMicroSDCardTerminalFactory;
import de.cardcontact.opencard.factory.SmartCardHSMCardServiceFactory;
import de.cardcontact.opencard.service.smartcardhsm.SmartCardHSMCardService;
import de.cardcontact.opencard.service.smartcardhsm.SmartCardHSMRSAKey;
import de.cardcontact.opencard.utils.StreamingAPDUTracer;
import opencard.core.service.CardRequest;
import opencard.core.service.CardServiceException;
import opencard.core.service.CardServiceFactory;
import opencard.core.service.CardServiceRegistry;
import opencard.core.service.SmartCard;
import opencard.core.terminal.CardTerminalException;
import opencard.core.terminal.CardTerminalRegistry;
import opencard.core.util.OpenCardPropertyLoadingException;

public class MainActivity extends AppCompatActivity {
    private static final String TAG = "PerformanceComp/MainActivity";
    private byte[] input16 = "aaaaaaaaaaaaaaaa".getBytes(StandardCharsets.UTF_8);
    private byte[] input32 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".getBytes(StandardCharsets.UTF_8);
    private byte[] input64 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".getBytes(StandardCharsets.UTF_8);
    private byte[] input128 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".getBytes(StandardCharsets.UTF_8);
    private byte[] input256 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".getBytes(StandardCharsets.UTF_8);
    private byte[] input512 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".getBytes(StandardCharsets.UTF_8);
    List inputs = new ArrayList();

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        /* Add different inputs to inputs list */
        inputs.add(input32);
        /* Import AES and RSA key to Android KeyStores */
        importAndroidKeyStoreKeys();
        startCollecting();

        Button hsmButton = (Button) findViewById(R.id.button1);
        hsmButton.setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) {
                Log.i(TAG, "Starting SmartCard-HSM Benchmark...");
                /*Log.i(TAG, "getCpuUsageFromFreqBefore: " + CpuInfo.getCpuUsageFromFreq());
                Log.i(TAG, "getCpuUsageSinceLastCallBefore: " + CpuInfo.getCpuUsageSinceLastCall());*/
                hsmTest();
                /*Log.i(TAG, "getCpuUsageFromFreqAfter: " + CpuInfo.getCpuUsageFromFreq());
                Log.i(TAG, "getCpuUsageSinceLastCallAfter: " + CpuInfo.getCpuUsageSinceLastCall());*/
            }
        });

        Button keyStoreButton = (Button) findViewById(R.id.button2);
        keyStoreButton.setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) {
                Log.v(TAG, "Starting AndroidKeyStore Benchmark...");
                /*Log.i(TAG, "getCpuUsageFromFreqBefore: " + CpuInfo.getCpuUsageFromFreq());
                Log.i(TAG, "getCpuUsageSinceLastCallBefore: " + CpuInfo.getCpuUsageSinceLastCall());*/
                keyStoreTest();
                Log.v(TAG, "Finished AndroidKeyStore Benchmark...");
                /*Log.i(TAG, "getCpuUsageFromFreqAfter: " + CpuInfo.getCpuUsageFromFreq());
                Log.i(TAG, "getCpuUsageSinceLastCallAfter: " + CpuInfo.getCpuUsageSinceLastCall());*/
            }
        });
    }

    /**
     * Function to test SmartCard-HSM.
     */
    private void hsmTest() {
        try {
            SmartCardHSMCardService smartCardService = getSmartCardHSMCardService();
            smartCardService.verifyPassword(null, 0, "123456".getBytes());
            SmartCardHSMRSAKey rsa2048Key = new SmartCardHSMRSAKey((byte) 0x3, "RSA-v1-5-SHA-256", (short) 2048);

            Debug.startMethodTracing("smartCardHSM.trace");
            /* Test RSA */
            //Log.i(TAG, "[*] Starting with RSA tests...");
            for(int input = 0; input < inputs.size(); input++) {
                //Log.i(TAG, "[**] Starting with " + 16*Math.pow(2, input) +  " bytes input...");
                for(int idx = 0; idx < 10; idx++) {
                    hsmOperationRSA(smartCardService, rsa2048Key, (byte[]) inputs.get(input));
                }
                //hsmOperationRSA(smartCardService, (byte[]) inputs.get(input));
            }
            /* Test AES */
            //Log.i(TAG, "[*] Starting with AES tests...");
            for(int input = 0; input < inputs.size(); input++) {
                //Log.i(TAG, "[**] Starting with " + 16*Math.pow(2, input) +  " bytes input...");
                for(int idx = 0; idx < 10; idx++) {
                    hsmOperationAES(smartCardService, (byte[]) inputs.get(input));
                }
                //hsmOperationAES(smartCardService, (byte[]) inputs.get(input));
            }
            Debug.stopMethodTracing();
        } catch (OpenCardPropertyLoadingException | CardServiceException | CardTerminalException | ClassNotFoundException e) {
            Log.e(TAG, Log.getStackTraceString(e));
        } finally {
            try {
                Log.i(TAG, "Shutting down.");
                SmartCard.shutdown();
            } catch (Exception e) {
                Log.i(TAG, Log.getStackTraceString(e));
            }
        }
    }

    /**
     * Function to test Android KeyStores.
     */
    private void keyStoreTest() {
        try {
            final KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
            keyStore.load(null);
            KeyStore.Entry keyEntryRSA = keyStore.getEntry("rsa_key", null);
            KeyStore.Entry keyEntryAES = keyStore.getEntry("aes_key", null);
            Signature sig = Signature.getInstance("SHA256WithRSA");
            sig.initSign(((KeyStore.PrivateKeyEntry) keyEntryRSA).getPrivateKey());
            Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, ((KeyStore.SecretKeyEntry) keyEntryAES).getSecretKey());

            Debug.startMethodTracing("keyStore.trace");
            /* Test RSA */
            //Log.i(TAG, "[*] Starting with RSA tests...");
            for(int input = 0; input < inputs.size(); input++) {
                //Log.i(TAG, "[**] Starting with " + 16*Math.pow(2, input) +  " bytes input...");
                for(int idx = 0; idx < 10; idx++) {
                    keyStoreOperationRSA(sig, (byte[]) inputs.get(input));
                }
                //keyStoreOperationRSA(keyEntryRSA, (byte[]) inputs.get(input));
            }
            /* Test AES */
            //Log.i(TAG, "[*] Starting with RSA tests...");
            for(int input = 0; input < inputs.size(); input++) {
                //Log.i(TAG, "[**] Starting with " + 16*Math.pow(2, input) +  " bytes input...");
                for(int idx = 0; idx < 10; idx++) {
                    keyStoreOperationAES(cipher, (byte[]) inputs.get(input));
                }
                //keyStoreOperationAES(keyEntryAES, (byte[]) inputs.get(input));
            }
            Debug.stopMethodTracing();
        } catch (NoSuchPaddingException | IllegalBlockSizeException | BadPaddingException | UnrecoverableEntryException | CertificateException | KeyStoreException | IOException | NoSuchAlgorithmException | SignatureException | InvalidKeyException e) {
            Log.i(TAG, Log.getStackTraceString(e));
        }
    }

    /**
     * Function to perform the RSA operation.
     */
    private void keyStoreOperationRSA(Signature sig, byte[] input) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        sig.update(input);
        sig.sign();
    }
    /**
     * Function to perform
     */
    private void keyStoreOperationAES(Cipher cipher, byte[] input) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        cipher.doFinal(input);
    }

    public String bytesToKey(final byte[] bytes) {
        final StringBuilder strSig = new StringBuilder();
        for (final byte aByte : bytes) {
            strSig.append(String.format("%02x", aByte));
        }
        return strSig.toString();
    }

    /**
     * Function to import AES and RSA keys.
     * RSA keys are in Downloads with "crt.pem" as certificate and "private_key.der" as private key.
     */
    private void importAndroidKeyStoreKeys() {
        /* Add RSA key */
        try {
            /* Get certificate in pem format and create Certificate */
            final Certificate cert = getCertificate("crt.pem");
            /* Get private key */
            final PrivateKey privateKey = getPrivateKey("private_key.der");
            /* add private key with cert to AndroidKeyStore Entries */
            addRSAKeyToAndroidKeyStore("rsa_key", cert, privateKey);
            Log.i(TAG, "RSA keys imported...");
        } catch (final IOException | CertificateException | NoSuchAlgorithmException | InvalidKeySpecException | KeyStoreException e) {
            Log.e(TAG, Log.getStackTraceString(e));
        }
        /* Add AES key */
        byte[] importKeyBytes = Base64.decode("ODX7mDoxHXVjVdD6pmXGadUWIDNOXX6rUNMA4Ofp3L8=", Base64.DEFAULT);
        SecretKey importKey = new SecretKeySpec(importKeyBytes, 0, importKeyBytes.length, "AES");
        Log.i(TAG, "AES keys imported...");
        try {
            addAESKeyToAndroidKeyStore("aes_key", importKey);
        } catch (KeyStoreException | CertificateException | IOException | NoSuchAlgorithmException e) {
            Log.e(TAG, Log.getStackTraceString(e));
        }
    }
    /**
     * Function to import AES keys.
     */
    private void addAESKeyToAndroidKeyStore(String alias, SecretKey importKey) throws KeyStoreException, CertificateException, IOException, NoSuchAlgorithmException {
        final KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
        keyStore.load(null);
        keyStore.setEntry(
                alias,
                new KeyStore.SecretKeyEntry(importKey),
                new KeyProtection.Builder(KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                        .setBlockModes(KeyProperties.BLOCK_MODE_ECB)
                        .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                        .setRandomizedEncryptionRequired(false)
                        //.setUserAuthenticationRequired(true)
                        //.setUserAuthenticationValidityDurationSeconds(6*60*60)
                        .build());
    }
    /**
     * Function to get RSA private key from keyFile in Download folder.
     */
    private PrivateKey getPrivateKey(final String keyFile) throws IOException, InvalidKeySpecException, NoSuchAlgorithmException {
        final String pathKey = Environment.getExternalStorageDirectory() + File.separator + "Download" + File.separator + keyFile;
        Log.i(TAG, "Using this path for private key: " + pathKey);
        final byte[] fileContentKey = Files.readAllBytes(Paths.get(pathKey));
        final PrivateKey privateKey =
                KeyFactory.getInstance("RSA").generatePrivate(
                        new PKCS8EncodedKeySpec(fileContentKey));
        return privateKey;
    }
    /**
     * Function to get RSA Certificate from crtFile in Download folder.
     */
    private Certificate getCertificate(final String crtFile) throws IOException, CertificateException {
        final String pathCrt = Environment.getExternalStorageDirectory() + File.separator + "Download" + File.separator + crtFile;
        Log.i(TAG, "Using this path for cert: " + pathCrt);
        final byte[] fileContentCrt = Files.readAllBytes(Paths.get(pathCrt));
        final Certificate cert =
                CertificateFactory.getInstance("X.509").generateCertificate(
                        new ByteArrayInputStream(fileContentCrt));
        return cert;
    }
    /**
     * Function to import RSA keys.
     */
    private void addRSAKeyToAndroidKeyStore(final String alias, final Certificate cert, final PrivateKey privateKey) throws KeyStoreException, CertificateException, IOException, NoSuchAlgorithmException {
        final KeyStore ks = KeyStore.getInstance("AndroidKeyStore");
        ks.load(null);
        ks.setEntry(
                alias,
                new KeyStore.PrivateKeyEntry(privateKey, new Certificate[] {cert}),
                new KeyProtection.Builder(KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT | KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY)
                        .setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA512)
                        .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_PKCS1)
                        .setSignaturePaddings(KeyProperties.SIGNATURE_PADDING_RSA_PKCS1)
                        //.setUserAuthenticationRequired(true)
                        //.setUserAuthenticationValidityDurationSeconds(6*60*60)
                        .build());
    }

    /**
     * Function to perform AES CBC encryption on input.
     */
    private void hsmOperationAES(SmartCardHSMCardService smartCardService, byte[] input) throws CardServiceException, CardTerminalException {
        smartCardService.deriveSymmetricKey((byte) 0x1, (byte) 0x10, input);
    }
    /**
     * Function to perform RSA signature on input.
     */
    private void hsmOperationRSA(SmartCardHSMCardService smartCardService, SmartCardHSMRSAKey rsa2048Key, byte[] input) throws CardServiceException, CardTerminalException {
        smartCardService.signHash(rsa2048Key, "SHA256withRSA", "PKCS1_V15", input);
    }

    /**
     * Function to return SmartCardHSMService.
     */
    @Nullable
    public SmartCardHSMCardService getSmartCardHSMCardService() throws OpenCardPropertyLoadingException, ClassNotFoundException, CardServiceException, CardTerminalException, CardTerminalException {
        /* Startup */
        Log.i(TAG, "OCF startup...");
        SmartCard.startup();
        Log.i(TAG, "Creating card terminal registry...");
        final CardTerminalRegistry ctr = CardTerminalRegistry.getRegistry();

        /* Add SwissBit card terminal to registry */
        final SBMicroSDCardTerminalFactory sbcardf = new SBMicroSDCardTerminalFactory(getApplicationContext());
        sbcardf.createCardTerminals(ctr, null);

        /* Creating service registry */
        Log.i(TAG, "Creating card service registry...");
        final CardServiceRegistry csr = CardServiceRegistry.getRegistry();

        /* Adding card service */
        Log.i(TAG, "Adding SmartCard-HSM card service...");
        final CardServiceFactory csf = new SmartCardHSMCardServiceFactory();
        csr.add(csf);

        Log.i(TAG, "Creating card request...");
        final CardRequest cr = new CardRequest(CardRequest.ANYCARD, null, SmartCardHSMCardService.class);
        final SmartCard sc = SmartCard.waitForCard(cr);
        if (sc == null) {
            Log.i("SmartCard-HSM", "Could not get smart card...");
            return null;
        }

        sc.setAPDUTracer(new StreamingAPDUTracer(new PrintStream(new LogCatOutputStream())));
        Log.i(TAG, "Card found");

        Log.i(TAG, "Trying to create card service...");
        return (SmartCardHSMCardService) sc.getCardService(SmartCardHSMCardService.class, true);
    }

    private void startCollecting() {
        Thread thread = new Thread() {
            @Override
            public void run() {
                /*try {
                    ProcessBuilder builder = new ProcessBuilder("top", "-q", "-oCMDLINE,%CPU", "-s2", "-b");
                    Process process = builder.start();
                    BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
                    String line;
                    while ((line = reader.readLine()) != null) {
                        Log.d(TAG, "line: " + line);
                    }
                    reader.close();
                    BufferedReader err_reader = new BufferedReader(new InputStreamReader(process.getErrorStream()));
                    while ((line = err_reader.readLine()) != null) {
                        Log.e(TAG, "error: " + line);
                    }
                    process.waitFor();
                } catch (Exception e) {
                    e.printStackTrace();
                }*/
            }
        };
        thread.start();
    }
}