package org.headscale.helper;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import java.net.HttpURLConnection;
import java.net.InetAddress;
import java.net.URL;

// Resolves a name or fetches a URL as an ordinary app would, so traffic and
// DNS go through the VPN. Result data is "ok <addrs|status>" or "error <e>":
//   am broadcast -n org.headscale.helper/.Probe --es resolve host.example
//   am broadcast -n org.headscale.helper/.Probe --es url http://100.64.0.1/
public class Probe extends BroadcastReceiver {
    @Override
    public void onReceive(Context context, Intent intent) {
        final PendingResult result = goAsync();
        final String host = intent.getStringExtra("resolve");
        final String url = intent.getStringExtra("url");

        // Network access is not allowed on the main thread.
        new Thread(() -> {
            String out;
            try {
                out = "ok " + (host != null ? resolve(host) : fetch(url));
            } catch (Exception e) {
                out = "error " + e;
            }
            result.setResultData(out);
            result.finish();
        }).start();
    }

    private static String resolve(String host) throws Exception {
        StringBuilder sb = new StringBuilder();
        for (InetAddress a : InetAddress.getAllByName(host)) {
            sb.append(a.getHostAddress()).append(' ');
        }
        return sb.toString().trim();
    }

    private static String fetch(String url) throws Exception {
        HttpURLConnection c = (HttpURLConnection) new URL(url).openConnection();
        c.setConnectTimeout(5000);
        c.setReadTimeout(5000);
        try {
            return Integer.toString(c.getResponseCode());
        } finally {
            c.disconnect();
        }
    }
}
