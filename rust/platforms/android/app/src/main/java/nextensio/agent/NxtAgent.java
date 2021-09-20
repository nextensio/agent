package nextensio.agent;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.ComponentName;
import android.content.ServiceConnection;
import android.os.IBinder;
import androidx.localbroadcastmanager.content.LocalBroadcastManager;
import androidx.appcompat.app.AppCompatActivity;
import android.os.Bundle;
import android.os.Debug;
import android.view.View;
import android.widget.Button;
import android.widget.TextView;
import android.util.Log;
import android.net.Uri;
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
import android.net.VpnService;
import android.content.Intent;

// This class is an android 'activity' class, ie this is the one that deals
// with UI and buttons and stuff. Based on all the UI/button activity it will
// then launch a 'service' class in NxtAgentService.java
public class NxtAgent extends AppCompatActivity {
    private static final String TAG = "NxtUi";
    private NxtAgentService agentService = null;
    private final static String FIRE_FOX = "org.mozilla.firefox";
    private final static String ANDROID_BROWSER = "com.android.browser";
    private WebAuthClient authClient;
    private SessionClient sessionClient;
    private static final int VPN_REQUEST_CODE = 0x0F;
    
    private OIDCConfig mOidcConfig = new OIDCConfig.Builder()
    .clientId("0oav0rc5g0E3irFto5d6")
    .redirectUri("nextensio.agent:/login")
    .endSessionRedirectUri("nextensio.agent:/logout")
    .scopes("openid", "email", "profile", "offline_access")
    .discoveryUri("https://login.nextensio.net/oauth2/default")
    .create();

    private BroadcastReceiver vpnStateReceiver = new BroadcastReceiver() {

        // This class launches the NxtAgentService class, which then does its job and 
        // broadcasts its vpn connection status which is received in this API
        @Override
        public void onReceive(Context context, Intent intent) {
            if (NxtAgentService.BROADCAST_VPN_STATE.equals(intent.getAction())) {
                if (agentService != null) {
                    vpnStatus(agentService.vpnReady);
                }
                Log.i(TAG, String.format("Message: VPN status %b, bound %b", 
                                        intent.getBooleanExtra("running", false), (agentService != null)));
            }
        }
    };

    private ServiceConnection connection = new ServiceConnection() {
        public void onServiceConnected(ComponentName className, IBinder service) {
            boolean first = (agentService == null);
            agentService = ((NxtAgentService.NxtAgentServiceBinder)service).getService();
            vpnStatus(agentService.vpnReady);
            if (first == true) {
                signin();
            }
            Log.i(TAG, "Agent Bound with service " + String.format("%s, vpn %b", className, agentService.vpnReady));
        }
        public void onServiceDisconnected(ComponentName className) {
        }
    };

    void doBindService() {
        // Attempts to establish a connection with the service.  We use an
        // explicit class name because we want a specific service
        // implementation that we know will be running in our own process
        if (!bindService(new Intent(NxtAgent.this, NxtAgentService.class),
                connection, 0)) {
            Log.e(TAG, "Bind failed");
        }
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

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (requestCode == VPN_REQUEST_CODE) {
            if (resultCode == RESULT_OK) {
                if (agentService == null) {
                    startService(new Intent(this, NxtAgentService.class));
                    doBindService();
                }
                Log.i(TAG, "VPN result ok");
            } else {
                Log.e(TAG, "VPN Result not-ok " + String.format(" = %d", resultCode));
            }
        }
    }

    private void startService() {
        Intent vpnIntent = VpnService.prepare(this);
        if (vpnIntent != null) {
            startActivityForResult(vpnIntent, VPN_REQUEST_CODE);
            Log.i(TAG, "New Vpn Intent");
        } else {
            onActivityResult(VPN_REQUEST_CODE, RESULT_OK, null);
            Log.i(TAG, "Existing Vpn Intent");
        }
    }

    void signin() {
        authClient.signIn(this, null);
        Log.i(TAG, "User signin");
    }

    // This gets called when user clicks the button to start VPN. The prepare()
    // call will throw a popup asking user for permission to allow VPN and the 
    // result of the user action is sent as a result message to callback onActivityResult()
    // If the user has already allowed the VPN, then we just call the callback right away
    private void toggleVPN() {
        if (agentService == null) {
            startService();
            return;
        }
        if (agentService.vpnReady == true) {
            agentService.stop();
            Log.i(TAG, "Stopped VPN");
        } else {
            signin();
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
        NxtApp app = (NxtApp) this.getApplicationContext();

        authClient = new Okta.WebAuthBuilder()
        .withConfig(mOidcConfig)
        .withContext(app)
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
                        app.SetTokens(agentService, tokens.getAccessToken(), tokens.getRefreshToken());
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
        vpnButton.setEnabled(true);
        vpnButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                toggleVPN();
            }
        });

        // Register to receive notification from the NxtAgentService class
        LocalBroadcastManager.getInstance(this).registerReceiver(vpnStateReceiver,
                new IntentFilter(NxtAgentService.BROADCAST_VPN_STATE));
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
        unbindService(connection);
    }    
}
