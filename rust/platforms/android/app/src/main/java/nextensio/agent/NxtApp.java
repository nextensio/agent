package nextensio.agent;
import android.app.Application;
import android.util.Log;
import java.util.Map;
import java.util.HashMap;
import java.util.UUID;
import org.json.JSONObject;
import org.json.JSONArray;
import org.json.JSONException;
import java.time.Instant;
import java.time.Duration;
import okhttp3.OkHttpClient;
import okhttp3.MediaType;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;
import okhttp3.HttpUrl;
import okhttp3.MultipartBody;
import java.io.IOException;
import java.util.concurrent.TimeUnit ;
import android.os.Build;
import java.lang.reflect.Method;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.apache.commons.net.util.SubnetUtils;


class NxtStats {
    int gateway_up;
    int gateway_flaps;
    int last_gateway_flap;
    int gateway_flows;
    int total_flows;
    int gateway_ip;

    native void nxtStats();
}

public class NxtApp extends Application {

    private String publicIP = "";
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
    private OkHttpClient client = new OkHttpClient.Builder()
                                    .connectTimeout(15, TimeUnit.SECONDS)
                                    .writeTimeout(15, TimeUnit.SECONDS)
                                    .readTimeout(15, TimeUnit.SECONDS)
                                    .build();
    private NxtAgentService agentService = null;
    private int keepalivecount = 0;

    public void SetTokens(NxtAgentService service, String access, String refresh) {
        agentService = service;
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
                    if (!accessToken.equals("")) {
                        doOnboard(); 
                    }
                    try { 
                        Thread.sleep(1000);
                    } catch (InterruptedException exception) {
                        Log.i(TAG, "Sleep failed");
                    }                  
                }
            }
        }).start();

        Log.i(TAG, "Loaded rust");
    }

    public void onCreate() {
    }


    private void doOnboard() {
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
        
        if ((!onboarded || force_onboard) && (agentService != null)) {
            controllerOnboard();
        }
    }

    private void getPublicIP() {
        try (java.util.Scanner s = new java.util.Scanner(new java.net.URL("https://api.ipify.org").openStream(), "UTF-8").useDelimiter("\\A")) {
            publicIP = s.next();
        } catch (java.io.IOException e) {
            
        }
    }

    private void refresh() {
        HttpUrl.Builder urlBuilder = HttpUrl.parse("https://login.nextensio.net/oauth2/default/v1/token?client_id=0oav0rc5g0E3irFto5d6&redirect_uri=http://localhost:8180/&response_type=code&scope=openid%20offline_access&grant_type=refresh_token&refresh_token=" + refreshToken).newBuilder();
        String url = urlBuilder.build().toString();
        RequestBody reqbody = RequestBody.create(null, new byte[0]);  
        try {
            Request request = new Request.Builder()
                                .header("Accept", "application/json")
                                .header("Content-Type", "application/x-www-form-urlencoded")
                                .header("cache-control", "no-cache")
                                .url(url)
                                .method("POST",reqbody)
                                .build();
            Response res = client.newCall(request).execute();
            try {
                JSONObject response = new JSONObject(res.body().string());
                accessToken = response.getString("access_token");
                refreshToken = response.getString("refresh_token");
                Log.i(TAG, "Refresh success");
            }  catch (final JSONException e)  {
                Log.i(TAG, "Refresh json exception: " + e.getMessage());
            }
        } catch (IOException e) {
            Log.i(TAG, "Refresh fail: " + e.getMessage());
        }
    }

    private void agentKeepalive()  {
        if ((keepalivecount % 4) == 0) {
            getPublicIP();
        }
        keepalivecount += 1;
        NxtStats stats = new NxtStats();
        stats.nxtStats();
        MediaType JSON = MediaType.parse("application/json; charset=utf-8");
        JSONObject json = new JSONObject();
        try {
            json.put("device", Build.HOST + " " + Build.BRAND + " " + Build.MANUFACTURER + " " + Build.MODEL);
            json.put("gateway", stats.gateway_ip);
            json.put("version", last_version);
            json.put("source", publicIP);
        }  catch (final JSONException e)  {
        }
        RequestBody reqbody = RequestBody.create(JSON, json.toString());
        HttpUrl.Builder urlBuilder = HttpUrl.parse("https://server.nextensio.net:8080/api/v1/global/get/keepaliverequest").newBuilder();
        String url = urlBuilder.build().toString();
        try {
            Request request = new Request.Builder()
                                .header("Authorization", "Bearer " + accessToken)
                                .url(url)
                                .method("POST",reqbody)
                                .build();
            Response res = client.newCall(request).execute();
            try {
                JSONObject response = new JSONObject(res.body().string());
                String version = response.getString("version");
                if (!version.equals(last_version)) {
                    Log.i(TAG, "Version mismatch: " + version + ":" + last_version);
                    force_onboard = true;
                }
            } catch (final JSONException e)  {
                Log.i(TAG, "Keepalive json exception: " + e.getMessage());
            }
        }  catch (IOException e) {
            Log.i(TAG, "Keepalive fail: " + e.getMessage());
        }
    }

    private void controllerOnboard() {
        HttpUrl.Builder urlBuilder = HttpUrl.parse("https://server.nextensio.net:8080/api/v1/global/get/onboard").newBuilder();
        String url = urlBuilder.build().toString();
        try {
            Request request = new Request.Builder()
                                .header("Authorization", "Bearer " + accessToken)
                                .url(url)
                                .build();
            Response res = client.newCall(request).execute();
            try {
                JSONObject response = new JSONObject(res.body().string());
                agentOnboard(response);
            } catch (final JSONException e)  {
                Log.i(TAG, "Onboard json exception: " + e.getMessage());
            }
        }  catch (IOException e) {
            Log.i(TAG, "Onboard fail " + e.getMessage());
        }
    }

    public static boolean isValidSubnet(String subnet) {
        try {
            new SubnetUtils(subnet);
            return true;
        } catch (IllegalArgumentException iae) {
             return false;
        }
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
            boolean splitTunnel = onboard.getBoolean("splittunnel");
            JSONArray cert = onboard.getJSONArray("cacert");
            byte[] cacert = new byte[cert.length()];
            for(int i = 0; i < cert.length(); i++) {
                cacert[i] = (byte)cert.getInt(i);
            }

            boolean attractAll = !splitTunnel;
            JSONArray dom = onboard.getJSONArray("domains");
            String[] domains = new String[dom.length()];
            String[] subnets = new String[dom.length()];
            int subnetCnt = 0;
            for(int i = 0; i < dom.length(); i++) {
                JSONObject d = dom.getJSONObject(i);
                domains[i] = d.getString("name");
                if (domains[i].equals("nextensio-default-internet")) {
                    attractAll = true;
                }
                if (isValidSubnet(domains[i])) {
                    subnets[subnetCnt] = domains[i];
                    subnetCnt++;
                }
            }
            
            String[] services = new String[0];

            String hostname = Build.HOST;
            String model = Build.BRAND + " " + Build.MANUFACTURER + " " + Build.MODEL;
            String osname = Build.VERSION.BASE_OS;
            String regex = "([0-9]+).([0-9]+).([0-9]+)";
            Pattern pattern = Pattern.compile(regex);
            Matcher matcher = pattern.matcher(Build.VERSION.RELEASE);
            int major = 0;
            int minor = 0;
            int patch = 0;
            if (matcher.matches()) {
                major = Integer.parseInt(matcher.group(1));
                minor = Integer.parseInt(matcher.group(2));
                patch = Integer.parseInt(matcher.group(3));
            }

            nxtOnboard(accessToken, uuid, userid, gateway, connectid, cluster, cacert, domains, services,
                       hostname, model, "android", osname, major, minor, patch);

            last_version = onboard.getString("version");
            keepalive = onboard.getInt("keepalive");
            if (keepalive == 0) {
                keepalive = 5 * 60;
            }
            onboarded = true;
            force_onboard = false;
            agentService.start(attractAll, subnets, subnetCnt);
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
                                          byte []cacert, String []domains,  String []services,
                                          String hostname, String model, String ostype, String osname,
                                          int major, int minor, int patch);
}
