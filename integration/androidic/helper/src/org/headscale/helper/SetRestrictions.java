package org.headscale.helper;

import android.app.admin.DevicePolicyManager;
import android.content.BroadcastReceiver;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.os.Bundle;

// Replaces the target package's managed configuration with the broadcast's
// extras:
//   am broadcast -n org.headscale.helper/.SetRestrictions \
//     --es package com.tailscale.ipn --es LoginURL http://... --es AuthKey ...
public class SetRestrictions extends BroadcastReceiver {
    @Override
    public void onReceive(Context context, Intent intent) {
        Bundle extras = intent.getExtras() == null ? new Bundle() : new Bundle(intent.getExtras());
        String pkg = extras.getString("package", "com.tailscale.ipn");
        extras.remove("package");

        DevicePolicyManager dpm = context.getSystemService(DevicePolicyManager.class);
        dpm.setApplicationRestrictions(new ComponentName(context, Admin.class), pkg, extras);
        setResultData("ok " + extras.keySet());
    }
}
