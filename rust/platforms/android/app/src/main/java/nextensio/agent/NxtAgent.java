package nextensio.agent;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.ComponentName;
import android.content.ServiceConnection;
import android.os.IBinder;
import android.net.VpnService;
import androidx.localbroadcastmanager.content.LocalBroadcastManager;
import androidx.appcompat.app.AppCompatActivity;
import android.os.Bundle;
import android.os.Debug;
import android.view.View;
import android.widget.Button;
import android.widget.TextView;
import android.util.Log;
import android.net.Uri;
import android.os.Handler;
import com.okta.oidc.OIDCConfig;
import com.okta.oidc.Okta;
import com.okta.oidc.AuthorizationStatus;
import com.okta.oidc.util.AuthorizationException;
import com.okta.oidc.RequestCallback;
import com.okta.oidc.ResultCallback;
import com.okta.oidc.Tokens;
import com.okta.oidc.clients.sessions.SessionClient;
import com.okta.oidc.net.response.IntrospectInfo;
import com.okta.oidc.net.params.TokenTypeHint;
import com.okta.oidc.clients.web.WebAuthClient;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import com.android.volley.Request;
import com.android.volley.RequestQueue;
import com.android.volley.Response;
import com.android.volley.VolleyError;
import com.android.volley.AuthFailureError;
import com.android.volley.toolbox.JsonObjectRequest;
import com.android.volley.toolbox.Volley;
import java.util.Map;
import java.util.HashMap;
import java.util.UUID;
import org.json.JSONObject;
import org.json.JSONArray;
import org.json.JSONException;

class NxtStats {
    int gateway_up;
    int gateway_flaps;
    int last_gateway_flap;
    int gateway_flows;
    int total_flows;

    native void nxtStats();
}

// This class is an android 'activity' class, ie this is the one that deals
// with UI and buttons and stuff. Based on all the UI/button activity it will
// then launch a 'service' class in NxtAgentService.java
public class NxtAgent extends AppCompatActivity {
    private static final int VPN_REQUEST_CODE = 0x0F;
    private static final String TAG = "NxtUi";
    private NxtAgentService agentService = null;
    private Handler handler = new Handler();
    private final static String FIRE_FOX = "org.mozilla.firefox";
    private final static String ANDROID_BROWSER = "com.android.browser";
    private WebAuthClient authClient;
    private SessionClient sessionClient;
    
    private OIDCConfig mOidcConfig = new OIDCConfig.Builder()
    .clientId("0oa2ncngj2cVUdS6b4x7")
    .redirectUri("nextensio.agent:/login")
    .endSessionRedirectUri("nextensio.agent:/logout")
    .scopes("openid", "email", "profile", "offline_access")
    .discoveryUri("https://dev-635657.okta.com/oauth2/default")
    .create();

    private Runnable runTask = new Runnable() {
        @Override
        public void run() {
            final TextView textview = (TextView)findViewById(R.id.status);
            NxtStats stats = new NxtStats();
            stats.nxtStats();
            String text = String.format("%s to Nextensio\n" + 
                                        "%d connection flaps, last flap %d seconds / %d mins ago\n" + 
                                        "Via Nextensio flows %d, Direct internet flows %d\n" +
                                        "Heap in-use %d MB, allocated %d MB\n", 
                                        (stats.gateway_up == 1 ? "Connected" : "Not Connected"),
                                        stats.gateway_flaps, stats.last_gateway_flap, stats.last_gateway_flap/60,
                                        stats.gateway_flows, stats.total_flows,
                                        (Debug.getNativeHeapSize() - Debug.getNativeHeapFreeSize())/(1024*1024),
                                        Debug.getNativeHeapAllocatedSize()/(1024*1024));
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
        authClient.signIn(this, null);
    }

    private void agentOnboard(String accessToken, JSONObject onboard) {
        try {
            String result = onboard.getString("Result");
            if (!result.equals("ok")) {
                // TODO: show the error some place
                Log.i(TAG, "Onboard result is not ok: " + result);
                return;
            }
            String uuid = UUID.randomUUID().toString();
            String userid = onboard.getString("userid");
            String host = onboard.getString("gateway");
            String connectid = onboard.getString("connectid");
            JSONArray cert = onboard.getJSONArray("cacert");
            byte[] cacert = new byte[cert.length()];
            for(int i = 0; i < cert.length(); i++) {
                cacert[i] = (byte)cert.getInt(i);
            }

            JSONArray dom = onboard.getJSONArray("domains");
            String[] domains = new String[dom.length()];
            for(int i = 0; i < dom.length(); i++) {
                domains[i] = dom.getString(i);
            }

            String[] services = new String[1];
            services[0] = connectid;

            nxtOnboard(accessToken, uuid, userid, host, connectid, cacert, domains, services);

        } catch (final JSONException e)  {
            // TODO: show the error some place
            Log.i(TAG, "Error parsing json");
            return;
        }
    }

    private void introspect() {
        try {
            sessionClient.introspectToken(sessionClient.getTokens().getAccessToken(),
                TokenTypeHint.REFRESH_TOKEN, new RequestCallback<IntrospectInfo, AuthorizationException>() {
                    @Override
                    public void onSuccess(@NonNull IntrospectInfo result) {
                        Log.i(TAG, "Introspect active" + result.isActive() + " username " + result.getUsername() + 
                                     " uid " + result.getUid() + " sub " + result.getSub() + " aud " + result.getAud() + 
                                    " iss " + result.getIss() + " exp " + result.getExp() + " dev " + result.getDeviceId() +
                                    " client " + result.getClientId() + " scope " + result.getScope() +
                                    " ttype " + result.getTokenType());
                    }
        
                    @Override
                    public void onError(String error, AuthorizationException exception) {
                        Log.i(TAG, "Introspect failed " + error + " desc " + exception.errorDescription);
                    }
                }
            );
        } catch (AuthorizationException e) {
            Log.i(TAG, "Introspect failed with exception");
        }
    }

    private void controllerOnboard(String accessToken) {
        String url = "https://server.nextensio.net:8080/api/v1/global/get/onboard";
        RequestQueue queue = Volley.newRequestQueue(this);
        JsonObjectRequest jsonObjectRequest = new JsonObjectRequest(Request.Method.GET, url, null, new Response.Listener<JSONObject>() {
            @Override
            public void onResponse(JSONObject response) {
                agentOnboard(accessToken, response);
            }
        }, new Response.ErrorListener() {
            @Override
            public void onErrorResponse(VolleyError error) {
                // TODO: Show the error some place
                Log.i(TAG, "Error calling " + url);
            }
        }) {
            @Override
            public Map getHeaders() throws AuthFailureError 
            { 
                HashMap headers = new HashMap(); 
                headers.put("Authorization", "Bearer " + accessToken); 
                return headers; 
            }
        }; 
        
        // Add the request to the RequestQueue.
        queue.add(jsonObjectRequest);
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

        authClient = new Okta.WebAuthBuilder()
        .withConfig(mOidcConfig)
        .withContext(this.getApplicationContext())
        .supportedBrowsers(ANDROID_BROWSER, FIRE_FOX)
        .setCacheMode(false).create();

        sessionClient = authClient.getSessionClient();
        authClient.registerCallback(new ResultCallback<AuthorizationStatus, AuthorizationException>() {
            @Override
            public void onSuccess(@NonNull AuthorizationStatus status) {
                if (status == AuthorizationStatus.AUTHORIZED) {
                    try {
                        //client is authorized.
                        Tokens tokens = sessionClient.getTokens();
                        controllerOnboard(tokens.getAccessToken());
                    } catch (AuthorizationException exception) {
                        return;
                    }
                } else if (status == AuthorizationStatus.SIGNED_OUT) {
                    // TODO: We need to tell agent about this so agent can stop forwarding and tear
                    // down tunnels etc..
                }
            }
    
            @Override
            public void onCancel() {
            }
    
            @Override
            public void onError(@Nullable String s, @Nullable AuthorizationException e) {
            }
        }, this);

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

    private static native void nxtOnboard(String accessToken, String uuid, String userid, String host,
                                          String connectid, byte []cacert, String []domains, String []services);

}
