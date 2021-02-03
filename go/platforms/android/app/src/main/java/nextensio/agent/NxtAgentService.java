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
import java.nio.channels.Selector;

public class NxtAgentService extends VpnService
{
    private static final String TAG = "NxtAgent";
    private static final String VPN_ADDRESS = "169.254.2.1"; // Select a link local IP
    private static final String VPN_ROUTE = "0.0.0.0"; 
    public static final String BROADCAST_VPN_STATE = "nextensio.agent.VPN_STATE";
    private static boolean isRunning = false;
    private ParcelFileDescriptor vpnInterface = null;
    private PendingIntent pendingIntent;


    @Override
    public void onCreate()
    {
        super.onCreate();
        isRunning = true;
        setupVPN();
        try
        {
            int fd = vpnInterface.detachFd();
            LocalBroadcastManager.getInstance(this).sendBroadcast(new Intent(BROADCAST_VPN_STATE).putExtra("running", true));
            Log.i(TAG, "Start ");
            nxtOn(fd);
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

    private static native int nxtOn(int tunFd);
}
