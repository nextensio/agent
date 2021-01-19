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
	shExpMatch(host, "*.zoom.us") ||
        shExpMatch(host, "*.radiantmediaplayer.com")) {
	
        return "PROXY 127.0.0.1:8081";
    }

    if (isInNet(host, "3.7.35.0", "255.255.255.127")     ||
        isInNet(host, "3.21.137.128", "255.255.255.127") ||
        isInNet(host, "3.22.11.0", "255.255.255.0") ||
	isInNet(host, "3.23.93.0", "255.255.255.0") ||
	isInNet(host, "3.25.41.128", "255.255.255.127") ||
	isInNet(host, "3.25.42.0", "255.255.255.127") ||
	isInNet(host, "3.25.49.0", "255.255.255.0") ||

	isInNet(host, "3.80.20.128", "255.255.255.127") ||
        isInNet(host, "3.96.19.0", "255.255.255.0") ||
	isInNet(host, "3.101.32.128", "255.255.255.127") ||
	isInNet(host, "3.101.52.0", "255.255.255.127") ||
	isInNet(host, "3.104.34.128", "255.255.255.127") ||
	isInNet(host, "3.120.121.0", "255.255.255.127") ||
	isInNet(host, "3.127.194.128", "255.255.255.127") ||

        isInNet(host, "3.208.72.0", "255.255.255.127") ||
	isInNet(host, "3.211.241.0", "255.255.255.127") ||
	isInNet(host, "3.235.69.0", "255.255.255.127") ||
	isInNet(host, "3.235.82.0", "255.255.254.0") ||

	isInNet(host, "4.34.125.128", "255.255.255.127") ||
	isInNet(host, "4.35.64.128", "255.255.255.127") ||

        isInNet(host, "8.5.128.0", "255.255.254.0") ||
	isInNet(host, "13.52.6.128", "255.255.255.127") ||
	isInNet(host, "13.52.146.0", "255.255.255.127") ||
	isInNet(host, "18.157.88.0", "255.255.255.0") ||
	isInNet(host, "18.205.93.128", "255.255.255.127") ||

	isInNet(host, "50.239.202.0", "255.255.254.0") ||
	isInNet(host, "50.239.204.0", "255.255.255.0") ||
        isInNet(host, "52.61.100.128", "255.255.255.127") ||
	isInNet(host, "52.81.151.128", "255.255.255.127") ||
	isInNet(host, "52.81.215.0", "255.255.255.0") ||
	isInNet(host, "52.202.62.192", "255.255.255.192") ||
	isInNet(host, "52.215.168.0", "255.255.255.127") ||
	
	isInNet(host, "64.125.62.0", "255.255.255.0") ||
	isInNet(host, "64.211.144.0", "255.255.255.0") ||
        isInNet(host, "65.39.152.0", "255.255.255.0") ||
	isInNet(host, "69.174.57.0", "255.255.255.0") ||
	isInNet(host, "69.174.108.0", "255.255.252.0") ||

	isInNet(host, "99.79.20.0", "255.255.255.127") ||
	isInNet(host, "101.36.167.0", "255.255.255.0") ||
	isInNet(host, "103.122.166.0", "255.255.254.0") ||
	isInNet(host, "109.94.160.0", "255.255.252.0") ||

        isInNet(host, "111.33.115.0", "255.255.255.127") ||
	isInNet(host, "111.33.181.0", "255.255.255.127") ||
	isInNet(host, "115.110.154.192", "255.255.255.192") ||
	isInNet(host, "115.114.56.192", "255.255.255.192") ||
	isInNet(host, "115.114.115.0", "255.255.255.192") ||
	isInNet(host, "115.114.131.0", "255.255.255.192") ||
	isInNet(host, "120.29.148.0", "255.255.255.0") ||

        isInNet(host, "129.151.0.0", "255.255.240.0") ||
	isInNet(host, "129.159.0.0", "255.255.240.0") ||
	isInNet(host, "130.61.164.0", "255.255.252.0") ||
	isInNet(host, "134.224.0.0", "255.255.0.0") ||
	isInNet(host, "140.238.128.0", "255.255.255.0") ||
	isInNet(host, "140.238.232.0", "255.255.252.0") ||
	isInNet(host, "144.195.0.0", "255.255.0.0") ||
        isInNet(host, "147.124.96.0", "255.255.224.0") ||
	isInNet(host, "149.137.0.0", "255.255.128.0") ||

	isInNet(host, "152.67.20.0", "255.255.255.0") ||
	isInNet(host, "152.67.118.0", "255.255.255.0") ||
	isInNet(host, "152.67.168.0", "255.255.252.0") ||
	isInNet(host, "152.67.180.0", "255.255.255.0") ||
	isInNet(host, "152.67.184.0", "255.255.252.0") ||
        isInNet(host, "152.67.240.0", "255.255.248.0") ||

	isInNet(host, "158.101.64.0", "255.255.255.0") ||
	isInNet(host, "160.1.56.128", "255.255.255.127") ||
	isInNet(host, "161.189.199.0", "255.255.255.127") ||
	isInNet(host, "161.199.136.0", "255.255.252.0") ||
	isInNet(host, "162.12.232.0", "255.255.252.0") ||
	isInNet(host, "162.255.36.0", "255.255.252.0") ||
        isInNet(host, "165.254.88.0", "255.255.254.0") ||

	isInNet(host, "168.138.16.0", "255.255.252.0") ||
	isInNet(host, "168.138.48.0", "255.255.255.0") ||
	isInNet(host, "168.138.56.0", "255.255.248.0") ||
	isInNet(host, "168.138.72.0", "255.255.255.0") ||
	isInNet(host, "168.138.96.0", "255.255.252.0") ||
	isInNet(host, "168.138.116.0", "255.255.252.0") ||
	isInNet(host, "168.138.244.0", "255.255.255.0") ||

        isInNet(host, "170.114.0.0", "255.255.0.0") ||
	isInNet(host, "173.231.80.0", "255.255.240.0") ||
	isInNet(host, "192.204.12.0", "255.255.252.0") ||

	isInNet(host, "193.122.32.0", "255.255.252.0") ||
	isInNet(host, "193.122.36.0", "255.255.252.0") ||
	isInNet(host, "193.122.208.0", "255.255.240.0") ||
	isInNet(host, "193.122.224.0", "255.255.240.0") ||
	isInNet(host, "193.122.240.0", "255.255.240.0") ||
	isInNet(host, "193.123.0.0", "255.255.224.0") ||
	isInNet(host, "193.123.40.0", "255.255.252.0") ||
	isInNet(host, "193.123.44.0", "255.255.252.0") ||
	isInNet(host, "193.123.128.0", "255.255.224.0") ||
	isInNet(host, "193.123.168.0", "255.255.248.0") ||
	isInNet(host, "193.123.192.0", "255.255.224.0") ||

	isInNet(host, "198.251.128.0", "255.255.128.0") ||
	isInNet(host, "202.177.207.128", "255.255.252.224") ||
	isInNet(host, "204.80.104.0", "255.255.248.0") ||
	isInNet(host, "204.141.28.0", "255.255.252.0") ||
	isInNet(host, "207.226.132.0", "255.255.255.0") ||
	isInNet(host, "209.9.211.0", "255.255.225.0") ||
	isInNet(host, "209.9.215.0", "255.255.225.0") ||

	isInNet(host, "213.19.144.0", "255.255.255.0") ||
	isInNet(host, "213.19.153.0", "255.255.255.0") ||
	isInNet(host, "213.224.140.0", "255.255.255.0") ||

	isInNet(host, "221.122.88.64", "255.255.252.224") ||
	isInNet(host, "221.122.88.128", "255.255.255.127") ||
	isInNet(host, "221.122.89.128", "255.255.225.127") ||
	isInNet(host, "221.123.139.192", "255.255.225.224")) {

        return "PROXY 127.0.0.1:8081";
    }

    return "DIRECT";
}