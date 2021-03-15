package nextensio.agent;
import android.app.Application;
import android.util.Log;

public class NxtApp extends Application {

    private static final String TAG = "NxtUi";

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
        Log.i(TAG, "Loaded rust");
    }

    private static native int nxtInit(int direct);
}