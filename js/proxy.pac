function FindProxyForURL(url, host) {
    if (shExpMatch(host, "*undefined.com") || 
        shExpMatch(host, "*.abcnews.com") || 
        shExpMatch(host, "*.cnn.com") || 
        shExpMatch(host, "*.cisco.com") || 
        shExpMatch(host, "speed.hetzner.de") || 
        shExpMatch(host, "gunicorn.org") ||
        shExpMatch(host, "*.facebook.com") ||
        shExpMatch(host, "*.uber.com") ||
        shExpMatch(host, "*.lyft.com") ||
        shExpMatch(host, "*.hp.com") ||
        shExpMatch(host, "*.juniper.net") || 
        shExpMatch(host, "*.sony.com") ||
        shExpMatch(host, "*.bose.com") ||
        shExpMatch(host, "*.twitter.com") ||
        shExpMatch(host, "*.snap.com") ||
        shExpMatch(host, "*.samsung.com") ||
        shExpMatch(host, "*.asus.com") ||
        shExpMatch(host, "*.digitalocean.com") ||
        shExpMatch(host, "*.microsoft.com") ||
        shExpMatch(host, "*.slack.com") ||
        shExpMatch(host, "*.lenovo.com") ||
        shExpMatch(host, "*.amd.com") ||
        shExpMatch(host, "*.intel.com") ||
        shExpMatch(host, "*.micron.com") ||
        shExpMatch(host, "*.broadcom.com") ||
        shExpMatch(host, "*.bestbuy.com") ||
        shExpMatch(host, "*.petco.com") ||
        shExpMatch(host, "*.petsmart.com") ||
        shExpMatch(host, "*.apple.com") ||
        shExpMatch(host, "*.umd.edu") ||
        shExpMatch(host, "sc.edu") ||
        shExpMatch(host, "sc.gov") ||
        shExpMatch(host, "discoversouthcarolina.com") ||
	shExpMatch(host, "*.kismis.org") ||
	shExpMatch(host, "*.youtube.com") ||
	shExpMatch(host, "*.ucla.edu") ||
	shExpMatch(host, "*.chevron.com") ||
        shExpMatch(host, "*.httpvshttps.com") ||
        shExpMatch(host, "anglesharp.azurewebsites.net") ||
        shExpMatch(host, "*.radiantmediaplayer.com")) {
        return "PROXY 127.0.0.1:8081";
    }
    return "DIRECT";
}