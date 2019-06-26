function FindProxyForURL(url, host) {
    if (shExpMatch(host, "*undefined.com") || 
        shExpMatch(host, "www.abcnews.com") || 
        shExpMatch(host, "www.cnn.com") || 
        shExpMatch(host, "www.cisco.com") || 
        shExpMatch(host, "speed.hetzner.de") || 
        shExpMatch(host, "gunicorn.org") ||
        shExpMatch(host, "www.facebook.com") ||
        shExpMatch(host, "www.uber.com") ||
        shExpMatch(host, "www.lyft.com") ||
        shExpMatch(host, "www.hp.com") ||
        shExpMatch(host, "www.juniper.net") || 
        shExpMatch(host, "www.sony.com") ||
        shExpMatch(host, "www.bose.com") ||
        shExpMatch(host, "www.twitter.com") ||
        shExpMatch(host, "www.snap.com") ||
        shExpMatch(host, "www.samsung.com") ||
        shExpMatch(host, "www.asus.com") ||
        shExpMatch(host, "www.digitalocean.com") ||
        shExpMatch(host, "www.microsoft.com") ||
        shExpMatch(host, "www.slack.com") ||
        shExpMatch(host, "www.lenovo.com") ||
        shExpMatch(host, "www.amd.com") ||
        shExpMatch(host, "www.intel.com") ||
        shExpMatch(host, "www.micron.com") ||
        shExpMatch(host, "www.broadcom.com") ||
        shExpMatch(host, "www.bestbuy.com") ||
        shExpMatch(host, "www.petco.com") ||
        shExpMatch(host, "www.petsmart.com") ||
        shExpMatch(host, "www.apple.com") ||
        shExpMatch(host, "www.umd.edu") ||
        shExpMatch(host, "sc.edu") ||
        shExpMatch(host, "sc.gov") ||
        shExpMatch(host, "discoversouthcarolina.com") ||
        shExpMatch(host, "bunny.kismis.org") ||
        shExpMatch(host, "www.httpvshttps.com") ||
        shExpMatch(host, "anglesharp.azurewebsites.net") ||
        shExpMatch(host, "www.radiantmediaplayer.com")) {
        return "PROXY 127.0.0.1:8081";
    }
    return "DIRECT";
}