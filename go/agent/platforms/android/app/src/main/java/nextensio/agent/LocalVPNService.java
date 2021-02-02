/*
** Copyright 2015, Mohamed Naufal
**
** Licensed under the Apache License, Version 2.0 (the "License");
** you may not use this file except in compliance with the License.
** You may obtain a copy of the License at
**
**     http://www.apache.org/licenses/LICENSE-2.0
**
** Unless required by applicable law or agreed to in writing, software
** distributed under the License is distributed on an "AS IS" BASIS,
** WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
** See the License for the specific language governing permissions and
** limitations under the License.
*/

package nextensio.agent;

import android.app.PendingIntent;
import android.content.Intent;
import android.net.VpnService;
import android.os.ParcelFileDescriptor;
import android.support.v4.content.LocalBroadcastManager;
import android.util.Log;

import java.io.Closeable;
import java.io.FileDescriptor;
import java.io.IOException;
import java.nio.channels.FileChannel;
import java.nio.channels.Selector;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class LocalVPNService extends VpnService
{
    private static final String TAG = "NxtAgent";
    private static final String VPN_ADDRESS = "169.254.2.1"; // Select a link local IP
    private static final String VPN_ROUTE = "0.0.0.0"; 
    public static final String BROADCAST_VPN_STATE = "nextensio.agent.VPN_STATE";
    private static boolean isRunning = false;
    private ParcelFileDescriptor vpnInterface = null;

    private PendingIntent pendingIntent;
    private ExecutorService executorService;


    @Override
    public void onCreate()
    {
        super.onCreate();
        isRunning = true;
        setupVPN();
        try
        {
            executorService = Executors.newFixedThreadPool(1);
            executorService.submit(new VPNRunnable(vpnInterface.getFileDescriptor()));
            LocalBroadcastManager.getInstance(this).sendBroadcast(new Intent(BROADCAST_VPN_STATE).putExtra("running", true));
            Log.i(TAG, "Start");
        }
        finally {
            
        }
    }

    private void setupVPN()
    {
        if (vpnInterface == null)
        {
            Builder builder = new Builder();
            builder.addAddress(VPN_ADDRESS, 32);
            builder.addRoute(VPN_ROUTE, 0);
            vpnInterface = builder.setSession(getString(R.string.app_name)).setConfigureIntent(pendingIntent).establish();
        }
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId)
    {
        return START_STICKY;
    }

    public static boolean isRunning()
    {
        return isRunning;
    }

    @Override
    public void onDestroy()
    {
        super.onDestroy();
        isRunning = false;
        executorService.shutdownNow();
        cleanup();
        Log.i(TAG, "Destroyed");
    }

    private void cleanup()
    {
        closeResources(vpnInterface);
    }

    private static void closeResources(Closeable... resources)
    {
        for (Closeable resource : resources)
        {
            try
            {
                resource.close();
            }
            catch (IOException e)
            {
                // Ignore
            }
            finally
            {
            }
        }
    }

    private static class VPNRunnable implements Runnable
    {
        private static final String TAG = "NxtThread";

        private FileDescriptor vpnFileDescriptor;


        public VPNRunnable(FileDescriptor vpnFileDescriptor)
        {
            this.vpnFileDescriptor = vpnFileDescriptor;
        }

        @Override
        public void run()
        {
            Log.i(TAG, "Read/write pkts from descriptor " + vpnFileDescriptor);

            try
            {
                while (true) {
                    Thread.sleep(10);
                }
            }
            catch (InterruptedException e)
            {
                Log.i(TAG, "Stopping");
            }
            finally
            {
            }
        }
    }
}
