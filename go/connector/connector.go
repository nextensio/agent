package main

import (
	"context"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/opentracing/opentracing-go"
	jaegercfg "github.com/uber/jaeger-client-go/config"
	jaegerlog "github.com/uber/jaeger-client-go/log"
	"github.com/uber/jaeger-lib/metrics/prometheus"
	common "gitlab.com/nextensio/common/go"
	"gitlab.com/nextensio/common/go/messages/nxthdr"
	"gitlab.com/nextensio/common/go/transport/netconn"
)

type flowKey struct {
	sport uint32
	dport uint32
	proto uint32
	src   string
	dest  string
}

type flowTuns struct {
	app  common.Transport
	gwRx common.Transport
}

var flowLock sync.RWMutex
var flows map[flowKey]*flowTuns

var gw_onboarded bool
var onboarded bool
var uniqueId string
var controller string
var regInfo RegistrationInfo
var regInfoLock sync.RWMutex
var mainCtx context.Context
var gwTun common.Transport
var gwStreams chan common.NxtStream
var appStreams chan common.NxtStream
var unique uuid.UUID
var idp *string
var clientid *string
var gateway *string
var keyFile *string
var sharedKey string
var cluster string
var ports []int = []int{}
var traceInitLock sync.Mutex
var wireTracer opentracing.Tracer
var globTracer opentracing.Tracer

func flowAdd(key *flowKey, app common.Transport) {
	flowLock.Lock()
	defer flowLock.Unlock()

	flows[*key] = &flowTuns{app: app, gwRx: nil}
}

func flowDel(key *flowKey) {
	flowLock.Lock()
	defer flowLock.Unlock()

	tun := flows[*key]
	if tun != nil {
		delete(flows, *key)
		if tun.gwRx != nil {
			tun.gwRx.Close()
		}
	}

}

func flowGet(key flowKey, gwRx common.Transport) common.Transport {
	flowLock.Lock()
	defer flowLock.Unlock()

	tun := flows[key]
	if tun != nil {
		tun.gwRx = gwRx
		return tun.app
	}
	return nil
}

func gwToAppClose(tun common.Transport, dest ConnStats, span *opentracing.Span) {
	tun.Close()
	if dest.Conn != nil {
		dest.Conn.Close()
	}
	if span != nil {
		(*span).Finish()
	}
}

func traceFlow(flow *nxthdr.NxtFlow) *opentracing.Span {
	if globTracer == nil || wireTracer == nil {
		return nil
	}
	// Do tracing only if TraceCtx is set
	if flow.TraceCtx == "" {
		return nil
	}
	// Fake "uber-trace-id" http header to create tracer spanCtx
	httpHdr := make(http.Header)
	httpHdr.Add("Uber-Trace-Id", flow.TraceCtx)
	spanCtx, serr := globTracer.Extract(opentracing.HTTPHeaders,
		opentracing.HTTPHeadersCarrier(httpHdr))
	if (serr != nil) || (spanCtx == nil) {
		return nil
	}
	if flow.WireSpanStartTime != "" {
		var startTime time.Time
		startTime.UnmarshalJSON([]byte(flow.WireSpanStartTime))
		span := wireTracer.StartSpan("On Wire", opentracing.StartTime(startTime), opentracing.FollowsFrom(spanCtx))
		span.Finish()
	}
	span := globTracer.StartSpan(cluster+"-"+regInfo.Userid,
		opentracing.FollowsFrom(spanCtx))
	span.SetTag("nxt-trace-source", cluster+"-"+regInfo.Userid)
	span.SetTag("nxt-trace-destagent", flow.DestAgent)
	span.SetTag("nxt-trace-requestid", flow.TraceRequestId)
	span.SetTag("nxt-trace-userid", flow.Userid)
	span.Tracer().Inject(
		span.Context(),
		opentracing.HTTPHeaders,
		opentracing.HTTPHeadersCarrier(httpHdr),
	)
	flow.TraceCtx = httpHdr.Get("Uber-Trace-Id")
	return &span
}

// Stream coming from the gateway, send data over tcp/udp socket on the connector
func gwToApp(lg *log.Logger, tun common.Transport, dest ConnStats) {
	var span *opentracing.Span
	var finishT time.Time

	for {
		hdr, buf, err := tun.Read()
		if err != nil {
			gwToAppClose(tun, dest, span)
			return
		}
		switch hdr.Hdr.(type) {
		case *nxthdr.NxtHdr_Onboard:
			lg.Println("Got onboard response")
			onboard := hdr.Hdr.(*nxthdr.NxtHdr_Onboard).Onboard
			initJaeger(lg, onboard)
		case *nxthdr.NxtHdr_Flow:
			if dest.Conn == nil {
				flow := hdr.Hdr.(*nxthdr.NxtHdr_Flow).Flow
				key := flowKey{src: flow.Source, dest: flow.Dest, sport: flow.Sport, dport: flow.Dport, proto: flow.Proto}
				dest.Conn = flowGet(key, tun)
				if dest.Conn == nil {
					if flow.Proto == common.TCP {
						dest.Conn = netconn.NewClient(mainCtx, lg, "tcp", flow.DestSvc, flow.Dport)
					} else {
						dest.Conn = netconn.NewClient(mainCtx, lg, "udp", flow.DestSvc, flow.Dport)
					}
					// the appStreams passed here never gets used
					e := dest.Conn.Dial(appStreams)
					if e != nil {
						gwToAppClose(tun, dest, span)
						return
					}

					// This flow is originated for the first time from the gateway
					// to connector, so lets create a reverse direction here. Otherwise
					// the flow is originated from the connector to gateway, so reverse already exists
					newTun := tun.NewStream(nil)
					if newTun == nil {
						gwToAppClose(tun, dest, span)
						return
					}
					span = traceFlow(flow)

					// copy the flow
					newFlow := *flow
					// Swap source and dest agents
					s, d := newFlow.SourceAgent, newFlow.DestAgent
					newFlow.SourceAgent, newFlow.DestAgent = d, s
					newFlow.ResponseData = true
					var timeout time.Duration
					if newFlow.Proto == common.TCP {
						timeout = TCP_AGER
					} else {
						timeout = UDP_AGER
					}
					go appToGw(lg, &dest, newTun, timeout, &newFlow, tun)
					if span != nil {
						t := time.Now()
						byteA, _ := t.MarshalJSON()
						newFlow.WireSpanStartTime = string(byteA)
						finishT = t
					}
				}
			}
			e := dest.Conn.Write(hdr, buf)
			if e != nil {
				gwToAppClose(tun, dest, span)
				return
			}
			if span != nil {
				var finishTime opentracing.FinishOptions
				finishTime.FinishTime = finishT
				(*span).FinishWithOptions(finishTime)
				span = nil
			}
			dest.Tx += 1
		}
	}
}

func appToGwClose(src *ConnStats, dest common.Transport, gwRx common.Transport, key *flowKey) {
	src.Conn.Close()
	dest.Close()
	if gwRx != nil {
		gwRx.Close()
	}
	if key != nil {
		flowDel(key)
	}
}

// Data coming back from a tcp/udp socket. Send the data over the gateway
// stream that initially created the socket
func appToGw(lg *log.Logger, src *ConnStats, dest common.Transport, timeout time.Duration, flow *nxthdr.NxtFlow, gwRx common.Transport) {

	var key *flowKey
	var destAgent string = ""
	// If the destination (Tx) closes, close the rx also so the entire goroutine exits and
	// the close is cascaded to the the cluster
	dest.CloseCascade(src.Conn)

	for {
		src.Conn.SetReadDeadline(time.Now().Add(timeout))
		rx := src.Rx
		tx := src.Tx
		hdr, buf, err := src.Conn.Read()
		if err != nil {
			ignore := false
			if err.Err != nil {
				if e, ok := err.Err.(net.Error); ok && e.Timeout() {
					// We have not had any rx/tx for the RFC stipulated flow ageout time period,
					// so close the session, this will trigger a cascade of closes upto the connector
					if rx == src.Rx && tx == src.Tx {
						lg.Println("Flow aged out", *flow)
					} else {
						ignore = true
					}
				}
			}
			if !ignore {
				appToGwClose(src, dest, gwRx, key)
				return
			}
		}
		src.Rx += 1
		// if hdr is nil, that means this is a gateway originated flow, if its non-nil then
		// its a connector originated flow (a "server" NetConn). If hdr is nil, then the
		// flow details are passed in as a copy of the flow that came in from the gateway.
		// If hdr is non-nil, that contains details parsed from the packet, so we construct
		// a flow using those parsed details
		if hdr == nil {
			hdr = &nxthdr.NxtHdr{}
			hdr.Hdr = &nxthdr.NxtHdr_Flow{Flow: flow}
		} else {
			// We are saving this flow in the hashtable only in the case of a "connector originated flow",
			// because when the response comes back from the gateway, we need tp find the socket for the
			// connector origin side of the flow. We could keep this common for connector/gateway originated
			// and cache the flow all the time, but there is no need as of today and hence why waste memory
			// since the bulk of the use case will be gateway originated flows
			flow = hdr.Hdr.(*nxthdr.NxtHdr_Flow).Flow
			if destAgent == "" {
				// TODO: Do we need the reginfoLock here ? I think not because when we get
				// onboarding results we are just replacing stuff rather than adding/deleting stuff
				for _, d := range regInfo.Domains {
					if strings.Contains(flow.DestSvc, d.Name) {
						destAgent = d.Name
					}
				}
				// No service advertised that matches the one we want
				if destAgent == "" {
					appToGwClose(src, dest, gwRx, key)
					return
				}
			}
			flow.SourceAgent = regInfo.ConnectID
			flow.DestAgent = destAgent
			flow.ResponseData = false
			if key == nil {
				key = &flowKey{src: flow.Source, dest: flow.Dest, sport: flow.Sport, dport: flow.Dport, proto: flow.Proto}
				flowAdd(key, src.Conn)
			}
		}
		e := dest.Write(hdr, buf)
		if e != nil {
			appToGwClose(src, dest, gwRx, key)
			return
		}
	}
}

func monitorController(lg *log.Logger) {
	var keepalive uint = 30
	force_onboard := false

	last_keepalive := time.Now()
	for {
		if onboarded {
			if uint(time.Since(last_keepalive).Seconds()) >= keepalive {
				force_onboard = ControllerKeepalive(lg, controller, sharedKey, regInfo.Version, uniqueId)
				last_keepalive = time.Now()
			}
		}
		if !onboarded || force_onboard {
			if ControllerOnboard(lg, controller, sharedKey) {
				onboarded = true
				force_onboard = false
				gw_onboarded = false
				if regInfo.Keepalive == 0 {
					keepalive = 5 * 60
				} else {
					keepalive = regInfo.Keepalive
				}
			}
		}
		time.Sleep(30 * time.Second)
	}
}

// If the gateway tunnel goes down for any reason, re-create a new tunnel
func monitorGw(lg *log.Logger) {
	for {
		if onboarded {
			if gwTun == nil || gwTun.IsClosed() {
				gw_onboarded = false
				// Override gateway if one is suppled on command line
				if *gateway != "" {
					regInfo.Gateway = *gateway
				}
				cluster = getClusterName(regInfo.Gateway)
				gwTun = DialGateway(mainCtx, lg, "websocket", &regInfo, gwStreams)
				if gwTun != nil {
					// The only data this will get is onboard response/control messages,
					// data does not flow on the first stream (stream 0)
					go gwToApp(lg, gwTun, ConnStats{})
				}
			} else {
				if !gw_onboarded {
					if OnboardTunnel(lg, gwTun, false, &regInfo, uniqueId) == nil {
						lg.Println("Onboarded with gateway")
						gw_onboarded = true
						// Note that we are not launching an goroutines to read/write out of this
						// stream (first stream to the gateway), appToGw() always creates a new
						// stream over this session. Eventually we will support L3 raw ip pkt mode
						// for our agent and at that time the first stream will be used to tx/rx
						// all L3 packets
					} else {
						gwTun.Close()
					}
				}
			}
		}
		time.Sleep(2 * time.Second)
	}
}

func getClusterName(gateway string) string {
	if len(gateway) <= len(".nextensio.net") {
		return "unknown"
	}
	end := len(gateway) - len(".nextensio.net")
	return gateway[0:end]
}

func args() {
	c := flag.String("controller", "server.nextensio.net:8080", "controller host:port")
	idp = flag.String("idp", "https://dev-24743301.okta.com", "IDP to use to onboard")
	clientid = flag.String("client", "0oav0q3hn65I4Zkmr5d6", "IDP client id")
	gateway = flag.String("gateway", "", "Gateway name")
	keyFile = flag.String("key", "/opt/nextensio/connector.key", "Secret Key file name")
	p := flag.String("ports", "", "Ports to listen on, comma seperated")
	flag.Parse()
	if *p != "" {
		plist := strings.Split(*p, ",")
		for _, l := range plist {
			p1, e := strconv.Atoi(l)
			if e != nil {
				fmt.Println("Ports need to be comma seperated integers: ", *p)
				os.Exit(1)
			}
			ports = append(ports, p1)
		}
	}
	controller = *c
	s, e := ioutil.ReadFile(*keyFile)
	if e != nil {
		fmt.Println("Cannot read from key file: ", *keyFile, e)
		os.Exit(1)
	}
	sharedKey = string(s)
	sharedKey = strings.TrimSpace(sharedKey)
	sharedKey = strings.TrimRight(strings.TrimLeft(sharedKey, "\n"), "\n")
	fmt.Println(*c, *idp, *clientid, *gateway, cluster, ports)
}

func svrListen(lg *log.Logger, conn *netconn.NetConn, port int) {
	for {
		conn.Listen(appStreams)
		lg.Fatalf("Listen failed on port ", port)
	}
}

func svrAccept(lg *log.Logger) {
	for {
		select {
		case stream := <-appStreams:
			if gwTun == nil {
				// We are not ready yet
				stream.Stream.Close()
			} else {
				newTun := gwTun.NewStream(nil)
				if newTun == nil {
					lg.Println("Cannot create new gateway stream")
					stream.Stream.Close()
				} else {
					// Right now we support only tcp
					var dest ConnStats
					dest.Conn = stream.Stream
					go appToGw(lg, &dest, newTun, TCP_AGER, nil, nil)
				}
			}
		}
	}
}

func initJaegerTrace(service string, lg *log.Logger, onboard *nxthdr.NxtOnboard, onWire bool) {
	collector_url := os.Getenv("JAEGER_COLLECTOR")
	if collector_url == "" {
		collector_url = onboard.JaegerCollector
	}
	cfg := &jaegercfg.Configuration{
		ServiceName: service,
		Sampler: &jaegercfg.SamplerConfig{
			Type:  "const",
			Param: 1,
		},
		Reporter: &jaegercfg.ReporterConfig{
			LogSpans:          true,
			CollectorEndpoint: collector_url,
		},
	}
	jLogger := jaegerlog.StdLogger
	debugLogger := jaegerlog.DebugLogAdapter(jLogger)
	jMetricsFactory := prometheus.New()
	var err error
	if onWire {
		wireTracer, _, err = cfg.NewTracer(jaegercfg.Logger(debugLogger))
	} else {
		globTracer, _, err = cfg.NewTracer(
			jaegercfg.Logger(debugLogger),
			jaegercfg.Metrics(jMetricsFactory),
		)
		opentracing.SetGlobalTracer(globTracer)
	}
	if err != nil {
		lg.Println("JaegerTraceInit Failed - %v", err)
		cfg.Disabled = true
	} else {
		lg.Println("JaegerTrace Initialized. Collector Endpoint:", collector_url)
	}
}

func initJaeger(lg *log.Logger, onboard *nxthdr.NxtOnboard) {
	// Tunnels can flap and multiple onboards can in theory happen in parallel
	// (although should be very rare in practise). Dont mess up trace init in
	// that scenario
	traceInitLock.Lock()
	defer traceInitLock.Unlock()

	if globTracer == nil {
		initJaegerTrace("nxt-"+regInfo.Tenant+"-trace", lg, onboard, false)
	}
	// The below trace is for generating spans for the duration when the packet is on
	// the wire (From dest.write() to read() from the tunnel on the other end of the tunnel)
	// Seperate instance of the Jaegertrace with different service name is needed to display
	// these gap spans in different colors compared to the spans generated from the above instance.
	if wireTracer == nil {
		initJaegerTrace("nxt-"+regInfo.Tenant+"-onwire-trace", lg, onboard, true)
	}
}

func main() {
	common.MAXBUF = (64 * 1024)
	mainCtx = context.Background()
	unique = uuid.New()
	gwStreams = make(chan common.NxtStream)
	appStreams = make(chan common.NxtStream)
	flows = make(map[flowKey]*flowTuns)
	lg := log.New(os.Stdout, "CNTR\n", 0)
	args()
	uniqueId = unique.String()
	go monitorController(lg)
	go monitorGw(lg)

	for _, p := range ports {
		// Right now we support only tcp
		conn := netconn.NewClient(mainCtx, lg, "tcp", "", uint32(p))
		go svrListen(lg, conn, p)
	}
	go svrAccept(lg)

	// Keep monitoring for new streams from either gateway or app direction,
	// and launch workers that will cross connect them to the other direction
	for {
		select {
		case stream := <-gwStreams:
			var dest ConnStats
			go gwToApp(lg, stream.Stream, dest)
		}
	}
}
