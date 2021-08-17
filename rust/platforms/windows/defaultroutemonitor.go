package main

import (
	"log"
	"sync"
	"time"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/services"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

func bindSocketRoute(family winipcfg.AddressFamily, ourLUID winipcfg.LUID, lastLUID *winipcfg.LUID, lastIndex *uint32, blackholeWhenLoop bool) error {
	r, err := winipcfg.GetIPForwardTable2(family)
	if err != nil {
		return err
	}
	lowestMetric := ^uint32(0)
	index := uint32(0)       // Zero is "unspecified", which for IP_UNICAST_IF resets the value, which is what we want.
	luid := winipcfg.LUID(0) // Hopefully luid zero is unspecified, but hard to find docs saying so.
	for i := range r {
		if r[i].DestinationPrefix.PrefixLength != 0 || r[i].InterfaceLUID == ourLUID {
			continue
		}
		ifrow, err := r[i].InterfaceLUID.Interface()
		if err != nil || ifrow.OperStatus != winipcfg.IfOperStatusUp {
			continue
		}

		iface, err := r[i].InterfaceLUID.IPInterface(family)
		if err != nil {
			continue
		}

		if r[i].Metric+iface.Metric < lowestMetric {
			lowestMetric = r[i].Metric + iface.Metric
			index = r[i].InterfaceIndex
			luid = r[i].InterfaceLUID
		}
	}
	if luid == *lastLUID && index == *lastIndex {
		return nil
	}
	*lastLUID = luid
	*lastIndex = index
	blackhole := blackholeWhenLoop && index == 0
	if family == windows.AF_INET {
		log.Printf("Binding v4 socket to interface %d (blackhole=%v)", index, blackhole)
	} else if family == windows.AF_INET6 {
		log.Printf("Binding v6 socket to interface %d (blackhole=%v)", index, blackhole)
	}
	return nil
}

func monitorDefaultRoutes(family winipcfg.AddressFamily, blackholeWhenLoop bool, ourLUID winipcfg.LUID) ([]winipcfg.ChangeCallback, error) {
	lastLUID := winipcfg.LUID(0)
	lastIndex := ^uint32(0)
	doIt := func() error {
		err := bindSocketRoute(family, ourLUID, &lastLUID, &lastIndex, blackholeWhenLoop)
		if err != nil {
			return err
		}
		return nil
	}
	err := doIt()
	if err != nil {
		return nil, err
	}

	firstBurst := time.Time{}
	burstMutex := sync.Mutex{}
	burstTimer := time.AfterFunc(time.Hour*200, func() {
		burstMutex.Lock()
		firstBurst = time.Time{}
		doIt()
		burstMutex.Unlock()
	})
	burstTimer.Stop()
	bump := func() {
		burstMutex.Lock()
		burstTimer.Reset(time.Millisecond * 150)
		if firstBurst.IsZero() {
			firstBurst = time.Now()
		} else if time.Since(firstBurst) > time.Second*2 {
			firstBurst = time.Time{}
			burstTimer.Stop()
			doIt()
		}
		burstMutex.Unlock()
	}

	cbr, err := winipcfg.RegisterRouteChangeCallback(func(notificationType winipcfg.MibNotificationType, route *winipcfg.MibIPforwardRow2) {
		if route != nil && route.DestinationPrefix.PrefixLength == 0 {
			bump()
		}
	})
	if err != nil {
		return nil, err
	}
	cbi, err := winipcfg.RegisterInterfaceChangeCallback(func(notificationType winipcfg.MibNotificationType, iface *winipcfg.MibIPInterfaceRow) {
		if notificationType == winipcfg.MibParameterNotification {
			bump()
		}
	})
	if err != nil {
		cbr.Unregister()
		return nil, err
	}
	return []winipcfg.ChangeCallback{cbr, cbi}, nil
}

type interfaceWatcherError struct {
	serviceError services.Error
	err          error
}
type interfaceWatcherEvent struct {
	luid   winipcfg.LUID
	family winipcfg.AddressFamily
}
type interfaceWatcher struct {
	errors chan interfaceWatcherError
	luid   winipcfg.LUID

	setupMutex              sync.Mutex
	interfaceChangeCallback winipcfg.ChangeCallback
	changeCallbacks4        []winipcfg.ChangeCallback
	changeCallbacks6        []winipcfg.ChangeCallback
	storedEvents            []interfaceWatcherEvent
}

func (iw *interfaceWatcher) setup(family winipcfg.AddressFamily) {
	var changeCallbacks *[]winipcfg.ChangeCallback
	var ipversion string
	if family == windows.AF_INET {
		changeCallbacks = &iw.changeCallbacks4
		ipversion = "v4"
	} else if family == windows.AF_INET6 {
		changeCallbacks = &iw.changeCallbacks6
		ipversion = "v6"
	} else {
		return
	}
	if len(*changeCallbacks) != 0 {
		for _, cb := range *changeCallbacks {
			cb.Unregister()
		}
		*changeCallbacks = nil
	}
	var err error

	log.Printf("Monitoring default %s routes", ipversion)
	*changeCallbacks, err = monitorDefaultRoutes(family, true, iw.luid)
	if err != nil {
		iw.errors <- interfaceWatcherError{services.ErrorBindSocketsToDefaultRoutes, err}
		return
	}
}

func watchInterface() (*interfaceWatcher, error) {
	var err error
	iw := &interfaceWatcher{
		errors: make(chan interfaceWatcherError, 2),
	}
	iw.interfaceChangeCallback, err = winipcfg.RegisterInterfaceChangeCallback(func(notificationType winipcfg.MibNotificationType, iface *winipcfg.MibIPInterfaceRow) {
		iw.setupMutex.Lock()
		defer iw.setupMutex.Unlock()

		if notificationType != winipcfg.MibAddInstance {
			return
		}
		if iw.luid == 0 {
			iw.storedEvents = append(iw.storedEvents, interfaceWatcherEvent{iface.InterfaceLUID, iface.Family})
			return
		}
		if iface.InterfaceLUID != iw.luid {
			return
		}
		iw.setup(iface.Family)
	})
	if err != nil {
		return nil, err
	}
	return iw, nil
}

func (iw *interfaceWatcher) Configure(luid winipcfg.LUID) {
	iw.setupMutex.Lock()
	defer iw.setupMutex.Unlock()

	iw.luid = luid
	for _, event := range iw.storedEvents {
		if event.luid == luid {
			iw.setup(event.family)
		}
	}
	iw.storedEvents = nil
}

func (iw *interfaceWatcher) Destroy() {
	iw.setupMutex.Lock()
	changeCallbacks4 := iw.changeCallbacks4
	changeCallbacks6 := iw.changeCallbacks6
	interfaceChangeCallback := iw.interfaceChangeCallback
	luid := iw.luid
	iw.setupMutex.Unlock()

	if interfaceChangeCallback != nil {
		interfaceChangeCallback.Unregister()
	}
	for _, cb := range changeCallbacks4 {
		cb.Unregister()
	}
	for _, cb := range changeCallbacks6 {
		cb.Unregister()
	}

	iw.setupMutex.Lock()
	if interfaceChangeCallback == iw.interfaceChangeCallback {
		iw.interfaceChangeCallback = nil
	}
	for len(changeCallbacks4) > 0 && len(iw.changeCallbacks4) > 0 {
		iw.changeCallbacks4 = iw.changeCallbacks4[1:]
		changeCallbacks4 = changeCallbacks4[1:]
	}
	for len(changeCallbacks6) > 0 && len(iw.changeCallbacks6) > 0 {
		iw.changeCallbacks6 = iw.changeCallbacks6[1:]
		changeCallbacks6 = changeCallbacks6[1:]
	}
	if luid != 0 && iw.luid == luid {
		// It seems that the Windows networking stack doesn't like it when we destroy interfaces that have active
		// routes, so to be certain, just remove everything before destroying.
		luid.FlushRoutes(windows.AF_INET)
		luid.FlushIPAddresses(windows.AF_INET)
		luid.FlushDNS(windows.AF_INET)
		luid.FlushRoutes(windows.AF_INET6)
		luid.FlushIPAddresses(windows.AF_INET6)
		luid.FlushDNS(windows.AF_INET6)
	}
	iw.setupMutex.Unlock()
}
