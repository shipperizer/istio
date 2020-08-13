package cilium

import (
	"fmt"

	xdsapi "github.com/envoyproxy/go-control-plane/envoy/api/v2"
	ldsv2 "github.com/envoyproxy/go-control-plane/envoy/api/v2/listener"
	http_conn "github.com/envoyproxy/go-control-plane/envoy/config/filter/network/http_connection_manager/v2"

	"istio.io/istio/pilot/pkg/model"
	istionetworking "istio.io/istio/pilot/pkg/networking"
	"istio.io/istio/pilot/pkg/networking/plugin"
	"istio.io/istio/pilot/pkg/networking/util"
)

const (
	CiliumBpfMetadata = "cilium.bpf_metadata"
	CiliumL7Policy = "cilium.l7policy"
)
// Plugin is a Cilium plugin.
type Plugin struct{}

// NewPlugin returns an instance of the Cilium plugin
func NewPlugin() plugin.Plugin {
	return Plugin{}
}

// OnOutboundListener is called whenever a new outbound listener is added to the LDS output for a given service.
// Can be used to add additional filters on the outbound path.
func (Plugin) OnOutboundListener(in *plugin.InputParams, mutable *istionetworking.MutableObjects) error {
	return configureListener(false, in, mutable)
}

// OnInboundListener is called whenever a new listener is added to the LDS output for a given service
// Can be used to add additional filters.
func (Plugin) OnInboundListener(in *plugin.InputParams, mutable *istionetworking.MutableObjects) error {
	return configureListener(true, in, mutable)
}

// OnVirtualListener implments the Plugin interface method.
func (Plugin) OnVirtualListener(in *plugin.InputParams, mutable *istionetworking.MutableObjects) error {
	// Virtual listeners are outbound listeners, see pilot/pkg/networking/plugin/mixer/mixer.go
	// But then Istio configures a listener named "virtualInbound", so we have to fixup the
	// ingress/egress directionality in Cilium filters as it can be misconfigured.
	return configureListener(false, in, mutable)
}

// OnOutboundCluster is called whenever a new cluster is added to the CDS output.
func (Plugin) OnOutboundCluster(in *plugin.InputParams, cluster *xdsapi.Cluster) {
}

// OnInboundCluster is called whenever a new cluster is added to the CDS output.
func (Plugin) OnInboundCluster(in *plugin.InputParams, cluster *xdsapi.Cluster) {
}

// OnOutboundRouteConfiguration is called whenever a new set of virtual hosts (a set of virtual hosts with routes) is
// added to RDS in the outbound path.
func (Plugin) OnOutboundRouteConfiguration(in *plugin.InputParams, routeConfiguration *xdsapi.RouteConfiguration) {
}

// OnInboundRouteConfiguration is called whenever a new set of virtual hosts are added to the inbound path.
func (Plugin) OnInboundRouteConfiguration(in *plugin.InputParams, routeConfiguration *xdsapi.RouteConfiguration) {
}

// OnInboundFilterChains is called whenever a plugin needs to setup the filter chains, including relevant filter chain configuration.
func (Plugin) OnInboundFilterChains(in *plugin.InputParams) []istionetworking.FilterChain {
	return nil
}

// OnInboundPassthrough is called whenever a new passthrough filter chain is added to the LDS output.
func (Plugin) OnInboundPassthrough(in *plugin.InputParams, mutable *istionetworking.MutableObjects) error {
	return nil
}

// OnInboundPassthroughFilterChains is called for plugin to update the pass through filter chain.
func (Plugin) OnInboundPassthroughFilterChains(in *plugin.InputParams) []istionetworking.FilterChain {
	return nil
}

func configureListener(ingress bool, in *plugin.InputParams, mutable *istionetworking.MutableObjects) error {
	node := in.Node
	if node.Type != model.SidecarProxy {
		// Only care about sidecar.
		return nil
	}

	if mutable.Listener == nil || (len(mutable.Listener.FilterChains) != len(mutable.FilterChains)) {
		return fmt.Errorf("expected same number of filter chains in listener (%d) and mutable (%d)", len(mutable.Listener.FilterChains), len(mutable.FilterChains))
	}

	ciliumListenerCfg := &BpfMetadata{IsIngress: ingress}
	listenerFilter := &ldsv2.ListenerFilter{Name: CiliumBpfMetadata}
	listenerFilter.ConfigType = &ldsv2.ListenerFilter_TypedConfig{TypedConfig: util.MessageToAny(ciliumListenerCfg)}
	mutable.Listener.ListenerFilters = append(mutable.Listener.ListenerFilters, listenerFilter)

	ciliumHttpCfg := &L7Policy{AccessLogPath: "/var/run/cilium/access_log.sock"}
	httpFilter := &http_conn.HttpFilter{Name: CiliumL7Policy}
	httpFilter.ConfigType = &http_conn.HttpFilter_TypedConfig{TypedConfig: util.MessageToAny(ciliumHttpCfg)}

	switch in.ListenerProtocol {
	case istionetworking.ListenerProtocolHTTP:
		for i := range mutable.Listener.FilterChains {
			mutable.FilterChains[i].HTTP = append(mutable.FilterChains[i].HTTP, httpFilter)
		}
		return nil
	case istionetworking.ListenerProtocolTCP:
		// For gateways, due to TLS termination, a listener marked as TCP could very well
		// be using a HTTP connection manager. So check the filterChain.listenerProtocol
		// to decide the type of filter to attach
		if !ingress && in.Node.Type == model.Router {
			for i := range mutable.FilterChains {
				if mutable.FilterChains[i].ListenerProtocol == istionetworking.ListenerProtocolHTTP {
					mutable.FilterChains[i].HTTP = append(mutable.FilterChains[i].HTTP, httpFilter)
				}
			}
		}
		return nil
	case istionetworking.ListenerProtocolAuto:
		for i := range mutable.FilterChains {
			if mutable.FilterChains[i].ListenerProtocol == istionetworking.ListenerProtocolHTTP {
				mutable.FilterChains[i].HTTP = append(mutable.FilterChains[i].HTTP, httpFilter)
			}
		}
		return nil
	}

	return fmt.Errorf("unknown listener type %v in cilium.configureListener", in.ListenerProtocol)
}
