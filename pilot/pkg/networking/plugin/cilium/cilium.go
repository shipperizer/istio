package cilium

import (
	"fmt"

	xdsapi "github.com/envoyproxy/go-control-plane/envoy/api/v2"
	ldsv2 "github.com/envoyproxy/go-control-plane/envoy/api/v2/listener"
	http_conn "github.com/envoyproxy/go-control-plane/envoy/config/filter/network/http_connection_manager/v2"
	"github.com/gogo/protobuf/types"

	"istio.io/istio/pilot/pkg/model"
	"istio.io/istio/pilot/pkg/networking/plugin"
)

// Plugin is a Cilium plugin.
type Plugin struct{}

// NewPlugin returns an instance of the Cilium plugin
func NewPlugin() plugin.Plugin {
	return Plugin{}
}

// OnOutboundListener is called whenever a new outbound listener is added to the LDS output for a given service.
// Can be used to add additional filters on the outbound path.
func (Plugin) OnOutboundListener(in *plugin.InputParams, mutable *plugin.MutableObjects) error {
	return configureListener(false, in, mutable)
}

// OnInboundListener is called whenever a new listener is added to the LDS output for a given service
// Can be used to add additional filters.
func (Plugin) OnInboundListener(in *plugin.InputParams, mutable *plugin.MutableObjects) error {
	return configureListener(true, in, mutable)
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
func (Plugin) OnInboundFilterChains(in *plugin.InputParams) []plugin.FilterChain {
	return nil
}

func configureListener(ingress bool, in *plugin.InputParams, mutable *plugin.MutableObjects) error {
	node := in.Node
	if node.Type != model.SidecarProxy {
		// Only care about sidecar.
		return nil
	}

	if mutable.Listener == nil || (len(mutable.Listener.FilterChains) != len(mutable.FilterChains)) {
		return fmt.Errorf("expected same number of filter chains in listener (%d) and mutable (%d)", len(mutable.Listener.FilterChains), len(mutable.FilterChains))
	}

	mutable.Listener.ListenerFilters = append(mutable.Listener.ListenerFilters, ldsv2.ListenerFilter{
		Name:       "cilium.bpf_metadata",
		ConfigType: &ldsv2.ListenerFilter_Config{
			Config: &types.Struct{Fields: map[string]*types.Value{
				"is_ingress": {Kind: &types.Value_BoolValue{BoolValue: ingress}},
			}}}})

	if in.ListenerProtocol == plugin.ListenerProtocolHTTP {
		httpFilter := &http_conn.HttpFilter{
			Name: "cilium.l7policy",
			ConfigType: &http_conn.HttpFilter_Config{
				Config: &types.Struct{Fields: map[string]*types.Value{
					"access_log_path": {Kind: &types.Value_StringValue{StringValue: "/var/run/cilium/access_log.sock"}},
					"is_ingress":      {Kind: &types.Value_BoolValue{BoolValue: ingress}},
				}}}}
		for i := range mutable.Listener.FilterChains {
			mutable.FilterChains[i].HTTP = append(mutable.FilterChains[i].HTTP, httpFilter)
		}
	}

	return nil
}
