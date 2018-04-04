package cilium

import (
	"fmt"

	xdsapi "github.com/envoyproxy/go-control-plane/envoy/api/v2"
	http_conn "github.com/envoyproxy/go-control-plane/envoy/config/filter/network/http_connection_manager/v2"
	google_protobuf "github.com/gogo/protobuf/types"

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
func (Plugin) OnOutboundCluster(env *model.Environment, node *model.Proxy, push *model.PushStatus,
        service *model.Service, servicePort *model.Port, cluster *xdsapi.Cluster) {
}

// OnInboundCluster is called whenever a new cluster is added to the CDS output.
func (Plugin) OnInboundCluster(env *model.Environment, node *model.Proxy, push *model.PushStatus,
        service *model.Service, servicePort *model.Port, cluster *xdsapi.Cluster) {
}

// OnOutboundRouteConfiguration is called whenever a new set of virtual hosts (a set of virtual hosts with routes) is
// added to RDS in the outbound path.
func (Plugin) OnOutboundRouteConfiguration(in *plugin.InputParams, routeConfiguration *xdsapi.RouteConfiguration) {
}

// OnInboundRouteConfiguration is called whenever a new set of virtual hosts are added to the inbound path.
func (Plugin) OnInboundRouteConfiguration(in *plugin.InputParams, routeConfiguration *xdsapi.RouteConfiguration) {
}

func configureListener(ingress bool, in *plugin.InputParams, mutable *plugin.MutableObjects) error {
	node := in.Node
	if node.Type != model.Sidecar {
		// Only care about sidecar.
		return nil
	}

	if mutable.Listener == nil || (len(mutable.Listener.FilterChains) != len(mutable.FilterChains)) {
		return fmt.Errorf("expected same number of filter chains in listener (%d) and mutable (%d)", len(mutable.Listener.FilterChains), len(mutable.FilterChains))
	}

	if in.ListenerProtocol == plugin.ListenerProtocolHTTP {
		httpFilter := &http_conn.HttpFilter{
			Name: "cilium.l7policy",
			Config: &google_protobuf.Struct{Fields: map[string]*google_protobuf.Value{
				"access_log_path": {&google_protobuf.Value_StringValue{StringValue: "/var/run/cilium/access_log.sock"}},
				"policy_name":     {&google_protobuf.Value_StringValue{StringValue: node.IPAddress}},
				"is_ingress":      {&google_protobuf.Value_BoolValue{BoolValue: ingress}},
			}}}
		for i := range mutable.Listener.FilterChains {
			mutable.FilterChains[i].HTTP = append(mutable.FilterChains[i].HTTP, httpFilter)
		}
	}

	return nil
}
