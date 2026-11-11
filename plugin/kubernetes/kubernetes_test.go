package kubernetes

import (
	"context"
	"net"
	"slices"
	"strings"
	"testing"

	"github.com/coredns/coredns/plugin"
	"github.com/coredns/coredns/plugin/etcd/msg"
	"github.com/coredns/coredns/plugin/kubernetes/object"
	"github.com/coredns/coredns/request"

	"github.com/miekg/dns"
	api "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	mcs "sigs.k8s.io/mcs-api/pkg/apis/v1alpha1"
)

func TestEndpointHostname(t *testing.T) {
	tests := []struct {
		ip               string
		hostname         string
		expected         string
		podName          string
		endpointNameMode bool
	}{
		{"10.11.12.13", "", "10-11-12-13", "", false},
		{"10.11.12.13", "epname", "epname", "", false},
		{"10.11.12.13", "", "10-11-12-13", "hello-abcde", false},
		{"10.11.12.13", "epname", "epname", "hello-abcde", false},
		{"10.11.12.13", "epname", "epname", "hello-abcde", true},
		{"10.11.12.13", "", "hello-abcde", "hello-abcde", true},
		{"2001:db8:3333:4444:5555:6666:7777:8888", "", "2001-db8-3333-4444-5555-6666-7777-8888", "", false},
		{"2001:db8:3333:4444:5555:6666::", "", "2001-db8-3333-4444-5555-6666--0", "", false},
	}
	for _, test := range tests {
		result := endpointHostname(object.EndpointAddress{IP: test.ip, Hostname: test.hostname, TargetRefName: test.podName}, test.endpointNameMode)
		if result != test.expected {
			t.Errorf("Expected endpoint name for (ip:%v hostname:%v) to be '%v', but got '%v'", test.ip, test.hostname, test.expected, result)
		}
	}
}

type APIConnServiceTest struct{}

func (APIConnServiceTest) HasSynced() bool                             { return true }
func (APIConnServiceTest) Run()                                        {}
func (APIConnServiceTest) Stop() error                                 { return nil }
func (APIConnServiceTest) PodIndex(string) []*object.Pod               { return nil }
func (APIConnServiceTest) SvcIndexReverse(string) []*object.Service    { return nil }
func (APIConnServiceTest) SvcExtIndexReverse(string) []*object.Service { return nil }
func (APIConnServiceTest) EpIndexReverse(string) []*object.Endpoints   { return nil }
func (APIConnServiceTest) Modified(ModifiedMode) int64                 { return 0 }

func (APIConnServiceTest) SvcIndex(string) []*object.Service {
	svcs := []*object.Service{
		{
			Name:       "svc1",
			Namespace:  "testns",
			ClusterIPs: []string{"10.0.0.1"},
			Ports: []api.ServicePort{
				{Name: "http", Protocol: "tcp", Port: 80},
			},
		},
		{
			Name:       "svc-dual-stack",
			Namespace:  "testns",
			ClusterIPs: []string{"10.0.0.2", "10::2"},
			Ports: []api.ServicePort{
				{Name: "http", Protocol: "tcp", Port: 80},
			},
		},
		{
			Name:       "hdls1",
			Namespace:  "testns",
			ClusterIPs: []string{api.ClusterIPNone},
		},
		{
			Name:         "external",
			Namespace:    "testns",
			ExternalName: "coredns.io",
			Type:         api.ServiceTypeExternalName,
			Ports: []api.ServicePort{
				{Name: "http", Protocol: "tcp", Port: 80},
			},
		},
	}
	return svcs
}

func (APIConnServiceTest) ServiceList() []*object.Service {
	svcs := []*object.Service{
		{
			Name:       "svc1",
			Namespace:  "testns",
			ClusterIPs: []string{"10.0.0.1"},
			Ports: []api.ServicePort{
				{Name: "http", Protocol: "tcp", Port: 80},
			},
		},
		{
			Name:       "svc-dual-stack",
			Namespace:  "testns",
			ClusterIPs: []string{"10.0.0.2", "10::2"},
			Ports: []api.ServicePort{
				{Name: "http", Protocol: "tcp", Port: 80},
			},
		},
		{
			Name:       "hdls1",
			Namespace:  "testns",
			ClusterIPs: []string{api.ClusterIPNone},
		},
		{
			Name:         "external",
			Namespace:    "testns",
			ExternalName: "coredns.io",
			Type:         api.ServiceTypeExternalName,
			Ports: []api.ServicePort{
				{Name: "http", Protocol: "tcp", Port: 80},
			},
		},
	}
	return svcs
}

func (APIConnServiceTest) EpIndex(string) []*object.Endpoints {
	eps := []*object.Endpoints{
		{
			Subsets: []object.EndpointSubset{
				{
					Addresses: []object.EndpointAddress{
						{IP: "172.0.0.1", Hostname: "ep1a"},
					},
					Ports: []object.EndpointPort{
						{Port: 80, Protocol: "tcp", Name: "http"},
					},
				},
			},
			Name:      "svc1-slice1",
			Namespace: "testns",
			Index:     object.EndpointsKey("svc1", "testns"),
		},
		{
			Subsets: []object.EndpointSubset{
				{
					Addresses: []object.EndpointAddress{
						{IP: "172.0.0.2"},
					},
					Ports: []object.EndpointPort{
						{Port: 80, Protocol: "tcp", Name: "http"},
					},
				},
			},
			Name:      "hdls1-slice1",
			Namespace: "testns",
			Index:     object.EndpointsKey("hdls1", "testns"),
		},
		{
			Subsets: []object.EndpointSubset{
				{
					Addresses: []object.EndpointAddress{
						{IP: "10.9.8.7", NodeName: "test.node.foo.bar"},
					},
				},
			},
		},
	}
	return eps
}

func (APIConnServiceTest) EndpointsList() []*object.Endpoints {
	eps := []*object.Endpoints{
		{
			Subsets: []object.EndpointSubset{
				{
					Addresses: []object.EndpointAddress{
						{IP: "172.0.0.1", Hostname: "ep1a"},
					},
					Ports: []object.EndpointPort{
						{Port: 80, Protocol: "tcp", Name: "http"},
					},
				},
			},
			Name:      "svc1-slice1",
			Namespace: "testns",
			Index:     object.EndpointsKey("svc1", "testns"),
		},
		{
			Subsets: []object.EndpointSubset{
				{
					Addresses: []object.EndpointAddress{
						{IP: "172.0.0.2"},
					},
					Ports: []object.EndpointPort{
						{Port: 80, Protocol: "tcp", Name: "http"},
					},
				},
			},
			Name:      "hdls1-slice1",
			Namespace: "testns",
			Index:     object.EndpointsKey("hdls1", "testns"),
		},
		{
			Subsets: []object.EndpointSubset{
				{
					Addresses: []object.EndpointAddress{
						{IP: "172.0.0.2"},
					},
					Ports: []object.EndpointPort{
						{Port: 80, Protocol: "tcp", Name: "http"},
					},
				},
			},
			Name:      "hdls1-slice2",
			Namespace: "testns",
			Index:     object.EndpointsKey("hdls1", "testns"),
		},
		{
			Subsets: []object.EndpointSubset{
				{
					Addresses: []object.EndpointAddress{
						{IP: "10.9.8.7", NodeName: "test.node.foo.bar"},
					},
				},
			},
		},
	}
	return eps
}

func (APIConnServiceTest) SvcImportIndex(string) []*object.ServiceImport {
	svcs := []*object.ServiceImport{
		{
			Name:       "svc1",
			Namespace:  "testns",
			Type:       mcs.ClusterSetIP,
			ClusterIPs: []string{"10.0.0.1"},
			Ports: []mcs.ServicePort{
				{Name: "http", Protocol: "tcp", Port: 80},
			},
		},
		{
			Name:       "svc-dual-stack",
			Namespace:  "testns",
			Type:       mcs.ClusterSetIP,
			ClusterIPs: []string{"10.0.0.2", "10::2"},
			Ports: []mcs.ServicePort{
				{Name: "http", Protocol: "tcp", Port: 80},
			},
		},
		{
			Name:       "hdls1",
			Namespace:  "testns",
			Type:       mcs.Headless,
			ClusterIPs: []string{},
		},
	}
	return svcs
}

func (APIConnServiceTest) ServiceImportList() []*object.ServiceImport {
	svcs := []*object.ServiceImport{
		{
			Name:       "",
			Namespace:  "testns",
			Type:       mcs.ClusterSetIP,
			ClusterIPs: []string{"10.0.0.1"},
			Ports: []mcs.ServicePort{
				{Name: "http", Protocol: "tcp", Port: 80},
			},
		},
		{
			Name:       "svc-dual-stack",
			Namespace:  "testns",
			Type:       mcs.ClusterSetIP,
			ClusterIPs: []string{"10.0.0.2", "10::2"},
			Ports: []mcs.ServicePort{
				{Name: "http", Protocol: "tcp", Port: 80},
			},
		},
		{
			Name:      "hdls1",
			Namespace: "testns",
			Type:      mcs.Headless,
		},
	}
	return svcs
}

func (APIConnServiceTest) McEpIndex(string) []*object.MultiClusterEndpoints {
	eps := []*object.MultiClusterEndpoints{
		{
			Endpoints: object.Endpoints{
				Subsets: []object.EndpointSubset{
					{
						Addresses: []object.EndpointAddress{
							{IP: "172.0.0.1", Hostname: "ep1a"},
						},
						Ports: []object.EndpointPort{
							{Port: 80, Protocol: "tcp", Name: "http"},
						},
					},
				},
				Name:      "svc1-slice1",
				Namespace: "testns",
				Index:     object.EndpointsKey("svc1", "testns"),
			},
			ClusterId: "cluster1",
		},
		{
			Endpoints: object.Endpoints{
				Subsets: []object.EndpointSubset{
					{
						Addresses: []object.EndpointAddress{
							{IP: "172.0.0.2"},
						},
						Ports: []object.EndpointPort{
							{Port: 80, Protocol: "tcp", Name: "http"},
						},
					},
				},
				Name:      "hdls1-slice1",
				Namespace: "testns",
				Index:     object.EndpointsKey("hdls1", "testns"),
			},
			ClusterId: "cluster1",
		},
	}
	return eps
}

func (APIConnServiceTest) GetNodeByName(_ctx context.Context, _name string) (*api.Node, error) {
	return &api.Node{
		ObjectMeta: meta.ObjectMeta{
			Name: "test.node.foo.bar",
		},
	}, nil
}

func (APIConnServiceTest) GetNamespaceByName(name string) (*object.Namespace, error) {
	return &object.Namespace{
		Name: name,
	}, nil
}

func TestServices(t *testing.T) {
	k := New([]string{"interwebs.test.", "clusterset.test."})
	k.opts.multiclusterZones = []string{"clusterset.test."}
	k.APIConn = &APIConnServiceTest{}

	type svcAns struct {
		host string
		key  string
	}
	type svcTest struct {
		qname  string
		qtype  uint16
		answer []svcAns
	}
	tests := []svcTest{
		// Cluster IP Services
		{qname: "svc1.testns.svc.interwebs.test.", qtype: dns.TypeA, answer: []svcAns{{host: "10.0.0.1", key: "/" + coredns + "/test/interwebs/svc/testns/svc1"}}},
		{qname: "_http._tcp.svc1.testns.svc.interwebs.test.", qtype: dns.TypeSRV, answer: []svcAns{{host: "10.0.0.1", key: "/" + coredns + "/test/interwebs/svc/testns/svc1"}}},
		{qname: "ep1a.svc1.testns.svc.interwebs.test.", qtype: dns.TypeA, answer: []svcAns{{host: "172.0.0.1", key: "/" + coredns + "/test/interwebs/svc/testns/svc1/ep1a"}}},

		// Dual-Stack Cluster IP Service
		{
			qname: "_http._tcp.svc-dual-stack.testns.svc.interwebs.test.",
			qtype: dns.TypeSRV,
			answer: []svcAns{
				{host: "10.0.0.2", key: "/" + coredns + "/test/interwebs/svc/testns/svc-dual-stack"},
				{host: "10::2", key: "/" + coredns + "/test/interwebs/svc/testns/svc-dual-stack"},
			},
		},

		// External Services
		{qname: "external.testns.svc.interwebs.test.", qtype: dns.TypeCNAME, answer: []svcAns{{host: "coredns.io", key: "/" + coredns + "/test/interwebs/svc/testns/external"}}},

		// Headless Services
		{qname: "hdls1.testns.svc.interwebs.test.", qtype: dns.TypeA, answer: []svcAns{{host: "172.0.0.2", key: "/" + coredns + "/test/interwebs/svc/testns/hdls1/172-0-0-2"}}},

		// ClusterSet MultiCluster IP Services
		{qname: "svc1.testns.svc.clusterset.test.", qtype: dns.TypeA, answer: []svcAns{{host: "10.0.0.1", key: "/" + coredns + "/test/clusterset/svc/testns/svc1"}}},
		{qname: "_http._tcp.svc1.testns.svc.clusterset.test.", qtype: dns.TypeSRV, answer: []svcAns{{host: "10.0.0.1", key: "/" + coredns + "/test/clusterset/svc/testns/svc1"}}},
		{qname: "ep1a.cluster1.svc1.testns.svc.clusterset.test.", qtype: dns.TypeA, answer: []svcAns{{host: "172.0.0.1", key: "/" + coredns + "/test/clusterset/svc/testns/svc1/cluster1/ep1a"}}},

		// Dual-Stack ClusterSet MultiCluster IP Service
		{
			qname: "_http._tcp.svc-dual-stack.testns.svc.clusterset.test.",
			qtype: dns.TypeSRV,
			answer: []svcAns{
				{host: "10.0.0.2", key: "/" + coredns + "/test/clusterset/svc/testns/svc-dual-stack"},
				{host: "10::2", key: "/" + coredns + "/test/clusterset/svc/testns/svc-dual-stack"},
			},
		},

		// Headless MultiCluster Services
		{qname: "hdls1.testns.svc.clusterset.test.", qtype: dns.TypeA, answer: []svcAns{{host: "172.0.0.2", key: "/" + coredns + "/test/clusterset/svc/testns/hdls1/cluster1/172-0-0-2"}}},
	}

	for i, test := range tests {
		zone := "interwebs.test."
		if strings.Contains(test.qname, "clusterset.test") {
			zone = "clusterset.test."
		}
		state := request.Request{
			Req:  &dns.Msg{Question: []dns.Question{{Name: test.qname, Qtype: test.qtype}}},
			Zone: zone,
		}
		svcs, e := k.Services(context.TODO(), state, false, plugin.Options{})
		if e != nil {
			t.Errorf("Test %d: got error '%v'", i, e)
			continue
		}
		if len(svcs) != len(test.answer) {
			t.Errorf("Test %d, expected %v answer, got %v", i, len(test.answer), len(svcs))
			continue
		}

		for j := range svcs {
			if test.answer[j].host != svcs[j].Host {
				t.Errorf("Test %d, expected host '%v', got '%v'", i, test.answer[j].host, svcs[j].Host)
			}
			if test.answer[j].key != svcs[j].Key {
				t.Errorf("Test %d, expected key '%v', got '%v'", i, test.answer[j].key, svcs[j].Key)
			}
		}
	}
}

func TestServicesAuthority(t *testing.T) {
	k := New([]string{"interwebs.test."})
	k.APIConn = &APIConnServiceTest{}

	type svcAns struct {
		host string
		key  string
	}
	type svcTest struct {
		localIPs []net.IP
		qname    string
		qtype    uint16
		answer   []svcAns
	}
	tests := []svcTest{
		{localIPs: []net.IP{net.ParseIP("1.2.3.4")}, qname: "ns.dns.interwebs.test.", qtype: dns.TypeA, answer: []svcAns{{host: "1.2.3.4", key: "/" + coredns + "/test/interwebs/dns/ns"}}},
		{localIPs: []net.IP{net.ParseIP("1.2.3.4")}, qname: "ns.dns.interwebs.test.", qtype: dns.TypeAAAA},
		{localIPs: []net.IP{net.ParseIP("1:2::3:4")}, qname: "ns.dns.interwebs.test.", qtype: dns.TypeA},
		{localIPs: []net.IP{net.ParseIP("1:2::3:4")}, qname: "ns.dns.interwebs.test.", qtype: dns.TypeAAAA, answer: []svcAns{{host: "1:2::3:4", key: "/" + coredns + "/test/interwebs/dns/ns"}}},
		{
			localIPs: []net.IP{net.ParseIP("1.2.3.4"), net.ParseIP("1:2::3:4")},
			qname:    "ns.dns.interwebs.test.",
			qtype:    dns.TypeNS, answer: []svcAns{
				{host: "1.2.3.4", key: "/" + coredns + "/test/interwebs/dns/ns"},
				{host: "1:2::3:4", key: "/" + coredns + "/test/interwebs/dns/ns"},
			},
		},
	}

	for i, test := range tests {
		k.localIPs = test.localIPs

		state := request.Request{
			Req:  &dns.Msg{Question: []dns.Question{{Name: test.qname, Qtype: test.qtype}}},
			Zone: k.Zones[0],
		}
		svcs, e := k.Services(context.TODO(), state, false, plugin.Options{})
		if e != nil {
			t.Errorf("Test %d: got error '%v'", i, e)
			continue
		}
		if test.answer != nil && len(svcs) != len(test.answer) {
			t.Errorf("Test %d, expected 1 answer, got %v", i, len(svcs))
			continue
		}
		if test.answer == nil && len(svcs) != 0 {
			t.Errorf("Test %d, expected no answer, got %v", i, len(svcs))
			continue
		}

		if test.answer == nil && len(svcs) == 0 {
			continue
		}

		for i, answer := range test.answer {
			if answer.host != svcs[i].Host {
				t.Errorf("Test %d, expected host '%v', got '%v'", i, answer.host, svcs[i].Host)
			}
			if answer.key != svcs[i].Key {
				t.Errorf("Test %d, expected key '%v', got '%v'", i, answer.key, svcs[i].Key)
			}
		}
	}
}

func BenchmarkServices(b *testing.B) {
	k := New([]string{"inter.webs.tests."})
	k.APIConn = APIConnServiceTest{}
	ctx := context.TODO()

	m := new(dns.Msg)
	m.SetQuestion("svc1.testns.svc.inter.webs.tests.", dns.TypeA)
	state := request.Request{Zone: k.Zones[0], Req: m}

	b.ReportAllocs()
	for b.Loop() {
		_, _ = k.Services(ctx, state, false, plugin.Options{})
	}
}

func BenchmarkServicesHeadless(b *testing.B) {
	k := New([]string{"inter.webs.tests."})
	k.APIConn = APIConnServiceTest{}
	ctx := context.TODO()

	m := new(dns.Msg)
	m.SetQuestion("hdls1.testns.svc.inter.webs.tests.", dns.TypeA)
	state := request.Request{Zone: k.Zones[0], Req: m}

	b.ReportAllocs()
	for b.Loop() {
		_, _ = k.Services(ctx, state, false, plugin.Options{})
	}
}

// apiConnPreferenceTest is a configurable dnsController fake for multicluster
// cluster preference tests. Three member clusters serve one headless
// ServiceImport (hdls1); drained clusters publish slices without ready
// addresses, and reversed flips informer iteration order to model a resync.
type apiConnPreferenceTest struct {
	drained  map[string]bool
	reversed bool
}

var _ dnsController = apiConnPreferenceTest{}

func (apiConnPreferenceTest) HasSynced() bool                             { return true }
func (apiConnPreferenceTest) Run()                                        {}
func (apiConnPreferenceTest) Stop() error                                 { return nil }
func (apiConnPreferenceTest) PodIndex(string) []*object.Pod               { return nil }
func (apiConnPreferenceTest) SvcIndex(string) []*object.Service           { return nil }
func (apiConnPreferenceTest) SvcIndexReverse(string) []*object.Service    { return nil }
func (apiConnPreferenceTest) SvcExtIndexReverse(string) []*object.Service { return nil }
func (apiConnPreferenceTest) ServiceList() []*object.Service              { return nil }
func (apiConnPreferenceTest) EndpointsList() []*object.Endpoints          { return nil }
func (apiConnPreferenceTest) EpIndex(string) []*object.Endpoints          { return nil }
func (apiConnPreferenceTest) EpIndexReverse(string) []*object.Endpoints   { return nil }
func (apiConnPreferenceTest) Modified(ModifiedMode) int64                 { return 0 }

func (apiConnPreferenceTest) GetNodeByName(_ context.Context, _ string) (*api.Node, error) {
	return &api.Node{}, nil
}

func (apiConnPreferenceTest) GetNamespaceByName(name string) (*object.Namespace, error) {
	return &object.Namespace{Name: name}, nil
}

func (a apiConnPreferenceTest) ServiceImportList() []*object.ServiceImport {
	return append(a.SvcImportIndex("hdls1.testns"), a.SvcImportIndex("vip1.testns")...)
}

func (apiConnPreferenceTest) SvcImportIndex(idx string) []*object.ServiceImport {
	switch idx {
	case "hdls1.testns":
		return []*object.ServiceImport{{Name: "hdls1", Namespace: "testns", Type: mcs.Headless}}
	case "vip1.testns":
		return []*object.ServiceImport{{
			Name:       "vip1",
			Namespace:  "testns",
			Type:       mcs.ClusterSetIP,
			ClusterIPs: []string{"10.0.0.9"},
			Ports:      []mcs.ServicePort{{Name: "http", Protocol: "tcp", Port: 80}},
		}}
	}
	return nil
}

func (a apiConnPreferenceTest) McEpIndex(idx string) []*object.MultiClusterEndpoints {
	if idx != "hdls1.testns" {
		return nil
	}
	clusters := []struct{ id, ip string }{
		{"cluster-east", "172.10.0.1"},
		{"cluster-west", "172.20.0.1"},
		{"cluster-north", "172.30.0.1"},
	}
	eps := make([]*object.MultiClusterEndpoints, 0, len(clusters))
	for _, c := range clusters {
		ep := &object.MultiClusterEndpoints{
			Endpoints: object.Endpoints{
				Name:      "hdls1-slice-" + c.id,
				Namespace: "testns",
				Index:     object.MultiClusterEndpointsKey("hdls1", "testns"),
				Subsets: []object.EndpointSubset{{
					Ports: []object.EndpointPort{{Port: 80, Protocol: "tcp", Name: "http"}},
				}},
			},
			ClusterId: c.id,
		}
		// A drained cluster still owns a slice, but it carries no ready address.
		if !a.drained[c.id] {
			ep.Subsets[0].Addresses = []object.EndpointAddress{{IP: c.ip}}
		}
		eps = append(eps, ep)
	}
	if a.reversed {
		slices.Reverse(eps)
	}
	return eps
}

func TestMultiClusterClusterPreference(t *testing.T) {
	const zone = "clusterset.test."

	newK := func(conn dnsController, preference []string) *Kubernetes {
		k := New([]string{zone})
		k.opts.multiclusterZones = []string{zone}
		k.opts.clusterPreference = preference
		k.APIConn = conn
		return k
	}
	query := func(k *Kubernetes, qname string, qtype uint16) ([]msg.Service, error) {
		state := request.Request{
			Req:  &dns.Msg{Question: []dns.Question{{Name: qname, Qtype: qtype}}},
			Zone: zone,
		}
		return k.Services(context.TODO(), state, false, plugin.Options{})
	}
	hosts := func(svcs []msg.Service) []string {
		out := make([]string, 0, len(svcs))
		for _, s := range svcs {
			out = append(out, s.Host)
		}
		return out
	}

	tests := []struct {
		name        string
		preference  []string
		drained     map[string]bool
		qname       string
		qtype       uint16
		wantHosts   []string
		wantErr     bool
		wantKeyPart string
	}{
		{
			name:      "no preference returns every cluster in informer order",
			qname:     "hdls1.testns.svc.clusterset.test.",
			qtype:     dns.TypeA,
			wantHosts: []string{"172.10.0.1", "172.20.0.1", "172.30.0.1"},
		},
		{
			name:        "highest priority cluster with endpoints wins",
			preference:  []string{"cluster-west", "cluster-east"},
			qname:       "hdls1.testns.svc.clusterset.test.",
			qtype:       dns.TypeA,
			wantHosts:   []string{"172.20.0.1"},
			wantKeyPart: "/cluster-west/",
		},
		{
			name:        "fallback to next preference cluster when drained",
			preference:  []string{"cluster-west", "cluster-east"},
			drained:     map[string]bool{"cluster-west": true},
			qname:       "hdls1.testns.svc.clusterset.test.",
			qtype:       dns.TypeA,
			wantHosts:   []string{"172.10.0.1"},
			wantKeyPart: "/cluster-east/",
		},
		{
			name:        "unlisted cluster used as stable fallback",
			preference:  []string{"cluster-west", "cluster-east"},
			drained:     map[string]bool{"cluster-west": true, "cluster-east": true},
			qname:       "hdls1.testns.svc.clusterset.test.",
			qtype:       dns.TypeA,
			wantHosts:   []string{"172.30.0.1"},
			wantKeyPart: "/cluster-north/",
		},
		{
			name:       "no eligible cluster is a name error",
			preference: []string{"cluster-west", "cluster-east"},
			drained:    map[string]bool{"cluster-west": true, "cluster-east": true, "cluster-north": true},
			qname:      "hdls1.testns.svc.clusterset.test.",
			qtype:      dns.TypeA,
			wantErr:    true,
		},
		{
			name:        "SRV narrows to the same cluster",
			preference:  []string{"cluster-west", "cluster-east"},
			qname:       "_http._tcp.hdls1.testns.svc.clusterset.test.",
			qtype:       dns.TypeSRV,
			wantHosts:   []string{"172.20.0.1"},
			wantKeyPart: "/cluster-west/",
		},
		{
			name:        "explicit cluster selector bypasses preference",
			preference:  []string{"cluster-west"},
			qname:       "172-10-0-1.cluster-east.hdls1.testns.svc.clusterset.test.",
			qtype:       dns.TypeA,
			wantHosts:   []string{"172.10.0.1"},
			wantKeyPart: "/cluster-east/",
		},
		{
			// The MCS grammar requires a cluster label on endpoint names;
			// a name without one keeps its existing empty answer even when
			// a preference is configured.
			name:       "endpoint name without cluster selector stays empty",
			preference: []string{"cluster-west"},
			qname:      "172-20-0-1.hdls1.testns.svc.clusterset.test.",
			qtype:      dns.TypeA,
			wantErr:    true,
		},
		{
			name:       "clusterset vip answer is unaffected by preference",
			preference: []string{"cluster-west"},
			drained:    map[string]bool{"cluster-west": true},
			qname:      "vip1.testns.svc.clusterset.test.",
			qtype:      dns.TypeA,
			wantHosts:  []string{"10.0.0.9"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			conn := apiConnPreferenceTest{drained: tc.drained}
			svcs, err := query(newK(conn, tc.preference), tc.qname, tc.qtype)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected a name error, got services %v", svcs)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got := hosts(svcs); !slices.Equal(got, tc.wantHosts) {
				t.Fatalf("hosts: got %v, want %v", got, tc.wantHosts)
			}
			for _, s := range svcs {
				if tc.wantKeyPart != "" && !strings.Contains(s.Key, tc.wantKeyPart) {
					t.Fatalf("key %q missing %q", s.Key, tc.wantKeyPart)
				}
			}
		})
	}

	t.Run("selection converges across informer resync reordering", func(t *testing.T) {
		pref := []string{"cluster-east", "cluster-west"}
		qname := "hdls1.testns.svc.clusterset.test."

		before, err := query(newK(apiConnPreferenceTest{}, pref), qname, dns.TypeA)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		// A resync may hand the indexer back in a different order; the
		// selected cluster must depend on observed state, not slice order.
		resynced, err := query(newK(apiConnPreferenceTest{reversed: true}, pref), qname, dns.TypeA)
		if err != nil {
			t.Fatalf("unexpected error after resync: %v", err)
		}
		if !slices.Equal(hosts(before), hosts(resynced)) {
			t.Fatalf("selection diverged after resync: %v vs %v", hosts(before), hosts(resynced))
		}
		if got := hosts(resynced); !slices.Equal(got, []string{"172.10.0.1"}) {
			t.Fatalf("expected cluster-east to win, got %v", got)
		}

		// Draining the preferred cluster moves the answer to the next one,
		// and restoring it converges straight back.
		drained, err := query(newK(apiConnPreferenceTest{drained: map[string]bool{"cluster-east": true}}, pref), qname, dns.TypeA)
		if err != nil {
			t.Fatalf("unexpected error while drained: %v", err)
		}
		if got := hosts(drained); !slices.Equal(got, []string{"172.20.0.1"}) {
			t.Fatalf("expected failover to cluster-west, got %v", got)
		}
		restored, err := query(newK(apiConnPreferenceTest{}, pref), qname, dns.TypeA)
		if err != nil {
			t.Fatalf("unexpected error after restore: %v", err)
		}
		if !slices.Equal(hosts(restored), hosts(before)) {
			t.Fatalf("selection failed to converge after restore: %v vs %v", hosts(restored), hosts(before))
		}
	})
}

func TestPreferredMultiClusterCluster(t *testing.T) {
	mkEp := func(cluster string, addrs []string, ports []object.EndpointPort) *object.MultiClusterEndpoints {
		ep := &object.MultiClusterEndpoints{ClusterId: cluster}
		ep.Name = "hdls1-slice-" + cluster
		ep.Namespace = "testns"
		ep.Index = object.MultiClusterEndpointsKey("hdls1", "testns")
		sub := object.EndpointSubset{Ports: ports}
		for _, ip := range addrs {
			sub.Addresses = append(sub.Addresses, object.EndpointAddress{IP: ip})
		}
		ep.Subsets = []object.EndpointSubset{sub}
		return ep
	}
	httpPort := []object.EndpointPort{{Port: 80, Protocol: "tcp", Name: "http"}}
	dnsPort := []object.EndpointPort{{Port: 53, Protocol: "udp", Name: "dns"}}

	eps := []*object.MultiClusterEndpoints{
		mkEp("cluster-a", []string{"10.0.0.1"}, dnsPort),
		mkEp("cluster-b", []string{"10.0.0.2"}, httpPort),
		mkEp("cluster-c", nil, httpPort),
	}

	k := New([]string{"clusterset.test."})
	k.opts.clusterPreference = []string{"cluster-a", "cluster-b"}
	base := recordRequest{service: "hdls1", namespace: "testns"}

	// A bare address query: cluster-a has ready addresses and any port matches.
	if got := k.preferredMultiClusterCluster(base, eps); got != "cluster-a" {
		t.Fatalf("bare query: got %q, want cluster-a", got)
	}

	// An http/tcp SRV query cannot be answered by cluster-a, so fail over.
	srv := base
	srv.port, srv.protocol = "http", "tcp"
	if got := k.preferredMultiClusterCluster(srv, eps); got != "cluster-b" {
		t.Fatalf("http/tcp query: got %q, want cluster-b", got)
	}

	// Preference IDs match EndpointSlice labels case-insensitively, and the
	// observed cluster ID spelling is what gets returned.
	k.opts.clusterPreference = []string{"Cluster-B"}
	if got := k.preferredMultiClusterCluster(srv, eps); got != "cluster-b" {
		t.Fatalf("case-insensitive match: got %q, want cluster-b", got)
	}
	k.opts.clusterPreference = []string{"cluster-a", "cluster-b"}

	// An endpoint hostname nobody carries means no eligible cluster.
	named := base
	named.endpoint = "ghost"
	if got := k.preferredMultiClusterCluster(named, eps); got != "" {
		t.Fatalf("unmatched endpoint: got %q, want empty", got)
	}

	// An explicit cluster selector disables narrowing altogether.
	pinned := base
	pinned.cluster = "cluster-c"
	if got := k.preferredMultiClusterCluster(pinned, eps); got != "" {
		t.Fatalf("pinned query: got %q, want empty", got)
	}

	// Unconfigured preference means no narrowing.
	k.opts.clusterPreference = nil
	if got := k.preferredMultiClusterCluster(base, eps); got != "" {
		t.Fatalf("unconfigured preference: got %q, want empty", got)
	}

	// With the only listed cluster drained, unlisted clusters take over in
	// stable cluster-ID order (cluster-m before cluster-z).
	k.opts.clusterPreference = []string{"cluster-a"}
	fallback := []*object.MultiClusterEndpoints{
		mkEp("cluster-z", []string{"10.0.0.9"}, httpPort),
		mkEp("cluster-m", []string{"10.0.0.8"}, httpPort),
		mkEp("cluster-a", nil, httpPort),
	}
	if got := k.preferredMultiClusterCluster(base, fallback); got != "cluster-m" {
		t.Fatalf("fallback tier: got %q, want cluster-m (stable cluster-ID order)", got)
	}
}
