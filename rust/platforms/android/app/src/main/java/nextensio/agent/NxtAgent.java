package nextensio.agent;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.ComponentName;
import android.content.ServiceConnection;
import android.os.Binder;
import android.os.IBinder;
import android.net.VpnService;
import android.support.v4.content.LocalBroadcastManager;
import android.support.v7.app.ActionBarActivity;
import android.os.Bundle;
import android.view.View;
import android.widget.Button;
import android.widget.TextView;
import android.util.Log;
import android.net.Uri;
import android.os.Handler;

class NxtStats {
    long heap;
    long mallocs;
    long frees;
    long paused;
    int gc;
    int goroutines;
    int conn;
    int disco;
    int discoSecs;
    int numflows;
    int directflows;

    //native void nxtStats();
}

// This class is an android 'activity' class, ie this is the one that deals
// with UI and buttons and stuff. Based on all the UI/button activity it will
// then launch a 'service' class in NxtAgentService.java
public class NxtAgent extends ActionBarActivity {
    private static final int VPN_REQUEST_CODE = 0x0F;
    private static final String TAG = "NxtUi";
    private NxtAgentService agentService = null;
    private Handler handler = new Handler();

    private Runnable runTask = new Runnable() {
        @Override
        public void run() {
            final TextView textview = (TextView)findViewById(R.id.status);
            NxtStats stats = new NxtStats();
            //stats.nxtStats();
            String text = String.format("%s to Nextensio-Rust\n" + 
                                        "%d connection flaps to nextensio, last flap %d seconds / %d mins ago\n" + 
                                        "Total heap in-use bytes %d, malloc count %d, free count %d (delta = %d)\n" + 
                                        "Goroutines in use %d, Total GC count %d, Total GC Pause Nanosecs %d\n" +
                                        "Via Nxt flows %d, Direct internet flows %d\n",
                                        (stats.conn == 1 ? "Connected" : "Not Connected"),
                                        stats.disco, stats.discoSecs, stats.discoSecs/60,
                                        stats.heap, stats.mallocs, stats.frees, stats.mallocs - stats.frees,
                                        stats.goroutines, stats.gc, stats.paused,
                                        stats.numflows, stats.directflows);
            textview.setText(text);
                                        
            // Repeat every 30 secs
            handler.postDelayed(this, 30000); 
        }
    };

    private BroadcastReceiver vpnStateReceiver = new BroadcastReceiver() {

        // This class launches the NxtAgentService class, which then does its job and 
        // broadcasts its vpn connection status which is received in this API
        @Override
        public void onReceive(Context context, Intent intent) {
            if (NxtAgentService.BROADCAST_VPN_STATE.equals(intent.getAction())) {
                if (intent.getBooleanExtra("destroyed", false)) {
                    doUnbindService();
                    Log.i(TAG, "Message: Service destroyed");
                }  else {
                    if (agentService != null) {
                        vpnStatus(agentService.vpnReady);
                    }
                    Log.i(TAG, String.format("Message: VPN status %b, bound %b", 
                                             intent.getBooleanExtra("running", false), (agentService != null)));
                }
            }
        }
    };

    // This connection stuff is to be able to access the NxtAgentService class 
    // and call the methods inside it, it creates a "binding" to the actual object
    // in memory that represents the NxtAgentService class. The bind/unbind stuff
    // is needed only if we want to access data inside that object or call methods
    // inside that object etc..
    private ServiceConnection connection = new ServiceConnection() {
        public void onServiceConnected(ComponentName className, IBinder service) {
            agentService = ((NxtAgentService.NxtAgentServiceBinder)service).getService();
            vpnStatus(agentService.vpnReady);
            Log.i(TAG, "Bound with service " + String.format("%s, vpn %b", className, agentService.vpnReady));
        }

        public void onServiceDisconnected(ComponentName className) {
            // This is called when the connection with the service has been
            // unexpectedly disconnected -- that is, its process crashed.
            // Because it is running in our same process, we should never
            // see this happen.
            agentService = null;
            Log.e(TAG, "Service disconnected");
        }
    };

    void doBindService() {
        // Attempts to establish a connection with the service.  We use an
        // explicit class name because we want a specific service
        // implementation that we know will be running in our own process
        // (and thus won't be supporting component replacement by other
        // applications).
        if (!bindService(new Intent(NxtAgent.this, NxtAgentService.class),
                connection, 0)) {
            Log.e(TAG, "Bind failed");
        }
    }

    void doUnbindService() {
        Log.i(TAG, "Unbind service");
        if (agentService != null) {
            // Release information about the service's state.
            unbindService(connection);
            agentService = null;
        }
        vpnStatus(false);
    }

    private void vpnStatus(boolean vpnOn) {
        final Button vpnButton = (Button) findViewById(R.id.vpn);
        vpnButton.setEnabled(true);
        if (vpnOn) {
            vpnButton.setText(R.string.stop_agent);
        } else {
            vpnButton.setText(R.string.start_agent);
        }
    }

    // This gets called when user clicks the button to start VPN. The prepare()
    // call will throw a popup asking user for permission to allow VPN and the 
    // result of the user action is sent as a result message to callback onActivityResult()
    // If the user has already allowed the VPN, then we just call the callback right away
    private void toggleVPN() {
        if (agentService == null) {
            Intent vpnIntent = VpnService.prepare(this);
            if (vpnIntent != null) {
                startActivityForResult(vpnIntent, VPN_REQUEST_CODE);
                Log.i(TAG, "New Vpn Intent");
            } else {
                onActivityResult(VPN_REQUEST_CODE, RESULT_OK, null);
                Log.i(TAG, "Existing Vpn Intent");
            }
        } else {
            agentService.stop();
            doUnbindService();
            Log.i(TAG, "Stopped VPN");
        }
    }

    // User is asking for a browser to do the authentication/login
    private void launchLogin() {
        Intent browserIntent = new Intent(Intent.ACTION_VIEW, Uri.parse("http://localhost:8180"));
        startActivity(browserIntent);
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (requestCode == VPN_REQUEST_CODE) {
            if (resultCode == RESULT_OK) {
                startService(new Intent(this, NxtAgentService.class));
                doBindService();
                Log.i(TAG, "VPN result ok");
            } else {
                doUnbindService();
                Log.e(TAG, "VPN Result not-ok " + String.format(" = %d", resultCode));
            }
        }
    }

    // When the app is created, android calls onCreate() followed by onResume().
    // onResume() is also called when the app goes from background to foreground.
    // When the app is created, we just setup the buttons and other UI elements. 
    // After that when the user clicks the buttons etc.., the registered callbacks 
    // are invoked and sets in motion the rest of the things
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_nextensio);

        // Setup the button to turn the vpn on/off
        final Button vpnButton = (Button)findViewById(R.id.vpn);
        vpnButton.setEnabled(false);
        vpnButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                toggleVPN();
            }
        });

        // Setup the button to launch a browser to login/authenticate
        final Button loginButton = (Button)findViewById(R.id.login);
        loginButton.setEnabled(true);
        loginButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                launchLogin();
            }
        });

        // Register to receive notification from the NxtAgentService class
        LocalBroadcastManager.getInstance(this).registerReceiver(vpnStateReceiver,
                new IntentFilter(NxtAgentService.BROADCAST_VPN_STATE));


        // Schedule a periodic task to collect stats etc.. from the golang world
        handler.post(runTask);
    }

    @Override
    protected void onResume() {
        super.onResume();
        // We start of saying VPN is off, we dont know because this UI element
        // might have just come back from a paused state whereas service keeps
        // running, so we try to see if there is a service by binding to it and
        // is so that will update the true vpn status - so there can be a momentary
        // (couple seconds at most ?) glitch where the vpn status is incorrect
        if (agentService == null) {
            vpnStatus(false);
            doBindService();
        } else {
            vpnStatus(agentService.vpnReady);
        }
        Log.i(TAG, "Resume");
    }

    @Override
    protected void onDestroy() {
        super.onDestroy();
        doUnbindService();
    }    
}
