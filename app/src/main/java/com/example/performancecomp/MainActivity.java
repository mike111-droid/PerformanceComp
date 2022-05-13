package com.example.performancecomp;

import androidx.annotation.Nullable;
import androidx.appcompat.app.AppCompatActivity;

import android.os.Bundle;
import android.util.Log;

import java.io.PrintStream;

import de.cardcontact.opencard.android.swissbit.SBMicroSDCardTerminalFactory;
import de.cardcontact.opencard.factory.SmartCardHSMCardServiceFactory;
import de.cardcontact.opencard.service.smartcardhsm.SmartCardHSMCardService;
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
    private static final String TAG = "WireGuard/HSMManager";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
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
}