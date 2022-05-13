/*
 * Copyright © 2017-2022 WireGuard LLC. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

package com.example.performancecomp;

import android.util.Log;

import java.io.IOException;
import java.io.OutputStream;

/**
 * Necessary Class for SmartCard-HSM interaction.
 */
public class LogCatOutputStream extends OutputStream {
    @Override
    public synchronized void write(byte[] buffer, int offset, int len) {
        Log.i("SmartCard-HSM", new String(buffer, offset, len));
    }

    @Override
    public void write(int oneByte) throws IOException {
    }
}
