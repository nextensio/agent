package nextensio.agent;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.net.VpnService;
import android.support.v4.content.LocalBroadcastManager;
import android.support.v7.app.ActionBarActivity;
import android.os.Bundle;
import android.view.View;
import android.widget.Button;


public class NxtAgent extends ActionBarActivity {
    private static final int VPN_REQUEST_CODE = 0x0F;
    private boolean waitingForVPNStart;
    private boolean goLoaded;
    private static Context context;
    

    private BroadcastReceiver vpnStateReceiver = new BroadcastReceiver() {
        @Override
        public void onReceive(Context context, Intent intent) {
            if (NxtAgentService.BROADCAST_VPN_STATE.equals(intent.getAction())) {
                if (intent.getBooleanExtra("running", false))
                    waitingForVPNStart = false;
            }
        }
    };

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        if (!goLoaded) {
            this.context = getApplicationContext();
            SharedLibraryLoader.loadSharedLibrary(this.context, "nxt-go");
            goLoaded = true;
        }
        setContentView(R.layout.activity_nextensio);
        final Button vpnButton = (Button)findViewById(R.id.agent);
        vpnButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                startVPN();
            }
        });
        waitingForVPNStart = false;
        LocalBroadcastManager.getInstance(this).registerReceiver(vpnStateReceiver,
                new IntentFilter(NxtAgentService.BROADCAST_VPN_STATE));
        nxtInit(0);
    }

    private void startVPN() {
        Intent vpnIntent = VpnService.prepare(this);
        if (vpnIntent != null)
            startActivityForResult(vpnIntent, VPN_REQUEST_CODE);
        else
            onActivityResult(VPN_REQUEST_CODE, RESULT_OK, null);
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (requestCode == VPN_REQUEST_CODE && resultCode == RESULT_OK) {
            waitingForVPNStart = true;
            startService(new Intent(this, NxtAgentService.class));
            enableButton(false);
        }
    }

    @Override
    protected void onResume() {
        super.onResume();

        enableButton(!waitingForVPNStart && !NxtAgentService.isRunning());
    }

    private void enableButton(boolean enable) {
        final Button vpnButton = (Button) findViewById(R.id.agent);
        if (enable) {
            vpnButton.setEnabled(true);
            vpnButton.setText(R.string.start_agent);
        }
        else {
            vpnButton.setEnabled(false);
            vpnButton.setText(R.string.stop_agent);
        }
    }

    private static native int nxtInit(int direct);
}
