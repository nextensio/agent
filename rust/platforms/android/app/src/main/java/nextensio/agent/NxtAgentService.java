package nextensio.agent;

import android.app.PendingIntent;
import android.content.Intent;
import android.net.VpnService;
import android.os.ParcelFileDescriptor;
import android.support.v4.content.LocalBroadcastManager;
import android.content.pm.PackageManager;
import android.util.Log;
import android.content.Context;
import android.os.Binder;
import android.os.IBinder;
import android.system.Os;
import java.io.Closeable;
import java.io.FileDescriptor;
import java.io.IOException;
import java.nio.channels.Selector;

// This class is an android 'service' class (ie it has nothing to do with UI etc..), 
// its job is to create the vpnService interface/file descriptors and pass it onto 
// the golang agent, thats about it.
public class NxtAgentService extends VpnService {
    private static final String TAG = "NxtSvc";
    private static final String VPN_ADDRESS = "169.254.2.1"; // Select a link local IP
    private static final String VPN_ROUTE = "0.0.0.0"; 
    public static final String BROADCAST_VPN_STATE = "nextensio.agent.VPN_STATE";
    private static Context context;
    private ParcelFileDescriptor vpnInterface;
    private int vpnFd = 0;
    private PendingIntent pendingIntent;
    private boolean goLoaded;
    private final IBinder mBinder = new NxtAgentServiceBinder();
    boolean vpnReady;

    // TODO: I am still not clear whether the onCreate here should load the golang libs
    // when the onCreate in NxtAgent.java already does that. But I remember some issues
    // with java complaining JNI not found unless its done in both places, not sure how
    // this class can be launched before NxtAgent is launched and has done its onCreate()
    @Override
    public void onCreate() {
        super.onCreate();
        setupVPN();
        if (!goLoaded) {
            this.context = getApplicationContext();
            SharedLibraryLoader.loadSharedLibrary(this.context, "nxt");
            goLoaded = true;
            Log.i(TAG, "Loaded golibs");
        } 
        try {
            if (vpnFd != 0) {
                // Call into the golang agent and ask it to start Rx/Tx on this fd
                vpnReady = true;
                nxtOn(vpnFd);
                LocalBroadcastManager.getInstance(this).sendBroadcast(new Intent(BROADCAST_VPN_STATE).putExtra("running", true));
                Log.i(TAG, "VPN Start " + String.format("Fd = %d", vpnFd));
            } else {
                vpnReady = false;
                LocalBroadcastManager.getInstance(this).sendBroadcast(new Intent(BROADCAST_VPN_STATE).putExtra("running", false));
                stop();
                Log.i(TAG, "VPN fail");
            }
        } finally {
            
        }
    }

    public void stop() {
        closeResources();
        stopSelf();
        Log.i(TAG, "Stopping vpn");
    }

    private void setupVPN() {
        if (vpnFd == 0) {
            Builder builder = new Builder();
            builder.addAddress(VPN_ADDRESS, 32);
            builder.addRoute(VPN_ROUTE, 0);
            try {
                // We dont want our own packets to be looped back via VPN to ourselves.
                // Usually android does that using a "socket.protect" call for each socket
                // we establish. But we are going to interface with golang and we dont want
                // to create some api back from golang to java for this purpose. Hopefully
                // this achieves the purpose. Later when we have an "allowed-application"
                // list, that also hopefully excludes ourselves automatically without the
                // need to call a socket.protect
                builder.addDisallowedApplication("nextensio.agent");
            } catch (PackageManager.NameNotFoundException e) {
                Log.i(TAG, "Unable to protect the entire application");
                return;
            }
            // rust code works with non-blocking sockets
            builder.setBlocking(false);
            vpnInterface = builder.setSession(getString(R.string.app_name)).setConfigureIntent(pendingIntent).establish();
            if (vpnInterface != null) {
                vpnFd = vpnInterface.detachFd();
            }
        }
    }

    // The binder is what comes into picture when NxtAgent.java calls doBindService()
    // to get a reference to the actual memory object running to provide this service
    public class NxtAgentServiceBinder extends Binder {
        NxtAgentService getService() {
            return NxtAgentService.this;
        }
    }

    @Override
    public void onRevoke () {
        onDestroy();
        Log.i(TAG, "Revoked");
    }

    @Override
    public IBinder onBind(Intent intent) {
        return mBinder;
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        return START_STICKY;
    }

    @Override
    public void onDestroy() {
        closeResources();
        LocalBroadcastManager.getInstance(this).sendBroadcast(new Intent(BROADCAST_VPN_STATE).putExtra("destroyed", true));
        Log.i(TAG, "Destroyed");
        super.onDestroy();
    }

    private void closeResources() {
        vpnReady = false;
        try {
            if (vpnFd != 0) {
                Log.i(TAG, "VPN CLOSE");
                vpnInterface.close();
                nxtOff(vpnFd);
                vpnFd = 0;
            }
        } catch (IOException e) {
            Log.e(TAG, "Error closing vpnFd");
        } finally {
        }
    }

    private static native int nxtOn(int tunFd);
    private static native int nxtOff(int tunFd);
}
