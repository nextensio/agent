package nextensio.agent;
import android.app.Application;
import android.util.Log;
import java.util.Map;
import java.util.HashMap;
import java.util.UUID;
import org.json.JSONObject;
import org.json.JSONArray;
import org.json.JSONException;
import com.android.volley.Request;
import com.android.volley.RequestQueue;
import com.android.volley.Response;
import com.android.volley.VolleyError;
import com.android.volley.AuthFailureError;
import com.android.volley.toolbox.JsonObjectRequest;
import com.android.volley.toolbox.Volley;
import java.time.Instant;
import java.time.Duration;

public class NxtApp extends Application {

    private String accessToken = "";
    private String refreshToken = "";
    private boolean onboarded = false;
    private boolean force_onboard = false;
    private String last_version = "";
    private String uuid = UUID.randomUUID().toString();
    private int keepalive = 30;
    private Instant last_keepalive = Instant.now();
    private Instant last_refresh = Instant.now();
    private static final String TAG = "NxtApp";
    private static final int VPN_REQUEST_CODE = 0x0F;

    public void SetTokens(String access, String refresh) {
        accessToken = access;
        refreshToken = refresh;
        force_onboard = true;
    }

    public NxtApp() {
        // this method fires only once per application start. 
        // getApplicationContext returns null here

        // Load the rust agent lib
        System.loadLibrary("nxt");
        new Thread(new Runnable() {
            public void run() {
                Thread.currentThread().setName("nextensio.worker");
                // Call into the rust agent asking to initialize/start of the world
                nxtInit(0);                    
            }
        }).start();

        new Thread(new Runnable() {
            public void run() {
                Thread.currentThread().setName("nextensio.onboard");
                while (true) {
                    doOnboard(); 
                    try { 
                        Thread.sleep(3000);
                    } catch (InterruptedException exception) {
                        Log.i(TAG, "Sleep failed");
                    }                  
                }
        }
        }).start();

        Log.i(TAG, "Loaded rust");
    }

    private void doOnboard() {
        if (accessToken == "") {
            return;
        }

        Instant now = Instant.now();

        if (onboarded) {
            long timeElapsed = Duration.between(last_keepalive, now).getSeconds();
            if (timeElapsed >= keepalive) {
                agentKeepalive();
                last_keepalive = now;
            }
        }

        long timeElapsed = Duration.between(last_refresh, now).getSeconds();
        // Okta has a one hour access token timeout
        if (timeElapsed > 45*60) {
            refresh();
            last_refresh = now;
        }
        
        if (!onboarded || force_onboard) {
            controllerOnboard();
        }
    }

    private void refresh() {
        String url = "https://dev-24743301.okta.com/oauth2/default/v1/token?client_id=0oav0rc5g0E3irFto5d6&redirect_uri=http://localhost:8180/&response_type=code&scope=openid%20offline_access&grant_type=refresh_token&refresh_token=" + refreshToken;
        RequestQueue queue = Volley.newRequestQueue(this);
        JsonObjectRequest jsonObjectRequest = new JsonObjectRequest(Request.Method.POST, url, null, new Response.Listener<JSONObject>() {
            @Override
            public void onResponse(JSONObject response) {
                try {
                    accessToken = response.getString("access_token");
                    refreshToken = response.getString("refresh_token");
                    force_onboard = true;
                } catch (final JSONException e)  {
                    Log.i(TAG, "refresh decode error");
                }
            }
        }, new Response.ErrorListener() {
            @Override
            public void onErrorResponse(VolleyError error) {
                // TODO: Show the error some place
                Log.i(TAG, "Error calling " + url + error.getMessage());
            }
        })  {
            @Override
            public Map getHeaders() throws AuthFailureError 
            { 
                HashMap headers = new HashMap(); 
                headers.put("Accept", "application/json");
                headers.put("Content-Type", "application/x-www-form-urlencoded");
                headers.put("cache-control", "no-cache");
                return headers; 
            }
        }; 
        
        // Add the request to the RequestQueue.
        queue.add(jsonObjectRequest);
    }

    private void agentKeepalive()  {
        String url = "https://server.nextensio.net:8080/api/v1/global/get/keepalive/" + last_version + "/" + uuid;
        RequestQueue queue = Volley.newRequestQueue(this);
        JsonObjectRequest jsonObjectRequest = new JsonObjectRequest(Request.Method.GET, url, null, new Response.Listener<JSONObject>() {
            @Override
            public void onResponse(JSONObject response) {
                try {
                    String version = response.getString("version");
                    if (!version.equals(last_version)) {
                        Log.i(TAG, "Version mismatch: " + version + ":" + last_version);
                        force_onboard = true;
                    }
                } catch (final JSONException e)  {
                    Log.i(TAG, "keepalive failed");
                }
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

    private void controllerOnboard() {
        String url = "https://server.nextensio.net:8080/api/v1/global/get/onboard";
        RequestQueue queue = Volley.newRequestQueue(this);
        JsonObjectRequest jsonObjectRequest = new JsonObjectRequest(Request.Method.GET, url, null, new Response.Listener<JSONObject>() {
            @Override
            public void onResponse(JSONObject response) {
                agentOnboard(response);
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

    private void agentOnboard(JSONObject onboard) {
        try {
            String result = onboard.getString("Result");
            if (!result.equals("ok")) {
                // TODO: show the error some place
                Log.i(TAG, "Onboard result is not ok: " + result);
                return;
            }

            String userid = onboard.getString("userid");
            String gateway = onboard.getString("gateway");
            String connectid = onboard.getString("connectid");
            String cluster = onboard.getString("cluster");
            JSONArray cert = onboard.getJSONArray("cacert");
            byte[] cacert = new byte[cert.length()];
            for(int i = 0; i < cert.length(); i++) {
                cacert[i] = (byte)cert.getInt(i);
            }

            JSONArray dom = onboard.getJSONArray("domains");
            String[] domains = new String[dom.length()];
            String[] dnsip = new String[dom.length()];
            int[] needdns = new int[dom.length()];
            for(int i = 0; i < dom.length(); i++) {
                JSONObject d = dom.getJSONObject(i);
                domains[i] = d.getString("name");
                dnsip[i] = d.getString("dnsip");
                if (d.getBoolean("needdns")) {
                    needdns[i] = 1;
                } else {
                    needdns[i] = 0;
                }
            }
            
            String[] services = new String[1];
            services[0] = connectid;
            Log.i(TAG, services[0]);

            nxtOnboard(accessToken, uuid, userid, gateway, connectid, cluster, cacert, domains, dnsip, needdns, services);

            last_version = onboard.getString("version");
            keepalive = onboard.getInt("keepalive");
            if (keepalive == 0) {
                keepalive = 5 * 60;
            }
            onboarded = true;
            force_onboard = false;
            Log.i(TAG, "nxtOnboard success");

        } catch (final JSONException e)  {
            // TODO: show the error some place
            Log.i(TAG, "Error parsing json");
            return;
        }
    }

    private static native int nxtInit(int direct);

    private static native void nxtOnboard(String accessToken, String uuid, String userid, String host,
                                          String connectid, String cluster, 
                                          byte []cacert, String []domains, String[] dnsip, int[] needdns, String []services);
}