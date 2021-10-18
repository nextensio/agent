package nextensio.agent;

import android.app.PendingIntent;
import android.content.Intent;
import android.net.VpnService;
import android.os.ParcelFileDescriptor;
import androidx.localbroadcastmanager.content.LocalBroadcastManager;
import android.content.pm.PackageManager;
import android.util.Log;
import android.os.Binder;
import android.os.IBinder;

import java.io.IOException;

// This class is an android 'service' class (ie it has nothing to do with UI etc..), 
// its job is to create the vpnService interface/file descriptors and pass it onto 
// the golang agent, thats about it.
public class NxtAgentService extends VpnService {
    private static final String TAG = "NxtSvc";
    private static final String VPN_ADDRESS = "169.254.2.1"; // Select a link local IP
    private static final String DEFAULT_ROUTE = "0.0.0.0"; 
    private static final String SPECIFIC_ROUTE = "100.64.0.0"; 
    private static final String DNS1_ROUTE = "8.8.8.8"; 
    private static final String DNS2_ROUTE = "8.8.4.4"; 
    public static final String BROADCAST_VPN_STATE = "nextensio.agent.VPN_STATE";
    private ParcelFileDescriptor vpnInterface;
    private int vpnFd = 0;
    private PendingIntent pendingIntent;
    private final IBinder mBinder = new NxtAgentServiceBinder();
    boolean vpnReady;

    @Override
    public void onCreate() {
        super.onCreate();
    }

    public void start(boolean attractAll, String[] subnets, int subnetCnt) {
        stop();
        setupVPN(attractAll, subnets, subnetCnt);
        try {
            if (vpnFd != 0) {
                // Call into the golang agent and ask it to start Rx/Tx on this fd
                vpnReady = true;
                nxtOn(vpnFd);
                LocalBroadcastManager.getInstance(this).sendBroadcast(new Intent(BROADCAST_VPN_STATE).putExtra("running", true));
                Log.i(TAG, "VPN Start " + String.format("Fd = %d", vpnFd));
            } else {
                Log.i(TAG, "VPN fail");
            }
        } finally {
            
        }
    }

    public void stop() {
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
        LocalBroadcastManager.getInstance(this).sendBroadcast(new Intent(BROADCAST_VPN_STATE).putExtra("running", false));
        Log.i(TAG, "Stopping vpn");
    }

    private void setupVPN(boolean attractAll, String[] subnets, int subnetCnt) {
        Builder builder = new Builder();
        builder.setMtu(1500);
        // rust agent works with non-blocking sockets
        builder.setBlocking(false);
        try {
            // We dont want our own packets to be looped back via VPN to ourselves.
            // Usually android does that using a "socket.protect" call for each socket
            // established from android code, but here we are dealing with sockets established
            // from the rust agent and for that we cant really call socket.protect per socket
            builder.addDisallowedApplication("nextensio.agent");
        } catch (PackageManager.NameNotFoundException e) {
            Log.i(TAG, "Unable to protect the entire application");
            return;
        }
        builder.addAddress(VPN_ADDRESS, 32);
        // Android has its own DNS wierdness. The ranking in terms of the most well behaved
        // OSes for DNS is apple first, windows second and worst being android. In apple, we
        // can precisely control which domain's dns request will get sent to which dns server,
        // which is awesome! In windows, it by default broadcasts dns requests to all dns 
        // servers (no domain name to server mapping), which is not awesome but well we can
        // live with it. In android, if a vpn does not advertise any dns servers, the dns 
        // requests will never get to us ! Dns requests seems to be sent directly out of the
        // wifi/lte interface. But for responding to private domains, we need to get dns 
        // requests. So if we add a dns server, then ALL DNS REQUESTS come to us - public and
        // private ! So we just add a set of legit public dns servers (TODO: make those configurable
        // via controller) so that the public ones are getting sent to the right destination IP,
        // the private ones we intercept and respond with a CG-NAT address range.
        builder.addRoute(DNS1_ROUTE, 32);
        builder.addRoute(DNS2_ROUTE, 32);
        builder.addDnsServer(DNS1_ROUTE);
        builder.addDnsServer(DNS2_ROUTE);
        if (attractAll == true) {
            // We are capturing ALL traffic
            builder.addRoute(DEFAULT_ROUTE, 0);
        } else {
            // We are capturing only "enterprise" traffic, we give out enterprise addresses
            // in the CG-NAT range (100.64.0.0/10). Also we need dns requests to come to us,
            // so we add 
            builder.addRoute(SPECIFIC_ROUTE, 10);
            for(int i = 0; i < subnetCnt; i++) {
                String[] parts = subnets[i].split("/");
                if (parts.length == 2) {
                    String ip = parts[0];
                    int masklen = Integer.parseInt(parts[1]);
                    try {
                        builder.addRoute(ip, masklen);
                    } catch (Exception e) {
                        Log.i(TAG, "Subnet Exception " + e + ", subnet " + parts[0] + ", mask " + parts[1]);
                    }
                }
            }
        }

        vpnInterface = builder.setSession(getString(R.string.app_name)).setConfigureIntent(pendingIntent).establish();
        if (vpnInterface != null) {
            vpnFd = vpnInterface.detachFd();
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
        stop();
        Log.i(TAG, "Destroyed");
        super.onDestroy();
    }


    private static native int nxtOn(int tunFd);
    private static native int nxtOff(int tunFd);
}
