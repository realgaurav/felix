// Copyright (c) 2020 Tigera, Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// +build fvtests

package fv_test

import (
	"context"
	"fmt"
	"os"
	"regexp"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/projectcalico/felix/fv/connectivity"
	"github.com/projectcalico/felix/fv/infrastructure"
	"github.com/projectcalico/felix/fv/tcpdump"
	"github.com/projectcalico/felix/fv/utils"
	"github.com/projectcalico/felix/fv/workload"
	"github.com/projectcalico/libcalico-go/lib/apiconfig"
	api "github.com/projectcalico/libcalico-go/lib/apis/v3"
	"github.com/projectcalico/libcalico-go/lib/clientv3"
	"github.com/projectcalico/libcalico-go/lib/ipam"
	"github.com/projectcalico/libcalico-go/lib/net"
	"github.com/projectcalico/libcalico-go/lib/options"
)

const (
	wireguardInterfaceNameDefault       = "wireguard.cali"
	wireguardMTUDefault                 = 1420
	wireguardRoutingRulePriorityDefault = "99"
	wireguardListeningPortDefault       = "51820"

	fakeWireguardPubKey = "jlkVyQYooZYzI2wFfNhSZez5eWh44yfq1wKVjLvSXgY="
)

var _ = infrastructure.DatastoreDescribe("WireGuard-Supported", []apiconfig.DatastoreType{apiconfig.Kubernetes}, func(getInfra infrastructure.InfraFactory) {
	//var _ = infrastructure.DatastoreDescribe("WireGuard-Supported", []apiconfig.DatastoreType{apiconfig.EtcdV3, apiconfig.Kubernetes}, func(getInfra infrastructure.InfraFactory) {
	const nodeCount = 3

	var (
		infra   infrastructure.DatastoreInfra
		felixes []*infrastructure.Felix
		client  clientv3.Interface

		wls      [nodeCount]*workload.Workload // simulated host workloads
		hws      [nodeCount]*workload.Workload
		cc       *connectivity.Checker
		tcpdumps []*tcpdump.TCPDump
	)

	BeforeEach(func() {
		// Run these tests only when the Host has Wireguard kernel module available.
		if os.Getenv("FELIX_FV_WIREGUARD_AVAILABLE") != "true" {
			Skip("Skipping Wireguard supported tests.")
		}

		infra = getInfra()
		felixes, client = infrastructure.StartNNodeTopology(nodeCount, wireguardTopologyOptions(), infra)

		// To allow all ingress and egress, in absence of any Policy.
		infra.AddDefaultAllow()

		for i := range wls {
			wlIP := fmt.Sprintf("10.65.%d.2", i)
			wlName := fmt.Sprintf("wl%d", i)

			err := client.IPAM().AssignIP(utils.Ctx, ipam.AssignIPArgs{
				IP:       net.MustParseIP(wlIP),
				HandleID: &wlName,
				Attrs: map[string]string{
					ipam.AttributeNode: felixes[i].Hostname,
				},
				Hostname: felixes[i].Hostname,
			})
			Expect(err).NotTo(HaveOccurred())

			wls[i] = workload.Run(felixes[i], wlName, "default", wlIP, "8055", "tcp")
			wls[i].ConfigureInDatastore(infra)

			hws[i] = workload.Run(felixes[i], fmt.Sprintf("host%d", i), "", felixes[i].IP, "8055", "tcp")

			felixes[i].TriggerDelayedStart()
		}

		cc = &connectivity.Checker{}
	})

	AfterEach(func() {
		if CurrentGinkgoTestDescription().Failed {
			for _, felix := range felixes {
				felix.Exec("ip", "link", "show")
				felix.Exec("ip", "rule", "list")
				felix.Exec("ip", "route", "show", "table", "all")
				felix.Exec("ip", "route", "show", "cached")
				felix.Exec("wg")
			}
		}

		for _, tcpdump := range tcpdumps {
			tcpdump.Stop()
		}

		for _, wl := range wls {
			wl.Stop()
		}
		for _, hw := range hws {
			hw.Stop()
		}
		for _, felix := range felixes {
			felix.Stop()
		}

		if CurrentGinkgoTestDescription().Failed {
			infra.DumpErrorData()
		}
		infra.Stop()
	})

	tcpdumpMatchCount := func(felixId int, matcherName string) func() int {
		return func() int {
			return tcpdumps[felixId].MatchCount(matcherName)
		}
	}

	Context("with Wireguard disabled in node-3", func() {
		BeforeEach(func() {
			// Disable Wireguard on 3rd "host".
			felixPID := felixes[2].GetFelixPID()
			disableWireguardForFelix(client, "node."+felixes[2].Hostname)
			// Wait for felix to restart.
			Eventually(felixes[2].GetFelixPID, "5s", "100ms").ShouldNot(Equal(felixPID))

			// Start tcpdump on each "host".
			for _, felix := range felixes {
				tcpdump := felix.AttachTCPDump("eth0")
				inTunnelPacketsPattern := fmt.Sprintf("IP %s\\.51820 > \\d+\\.\\d+\\.\\d+\\.\\d+\\.51820: UDP", felix.IP)
				tcpdump.AddMatcher("numInTunnelPackets", regexp.MustCompile(inTunnelPacketsPattern))
				outTunnelPacketsPattern := fmt.Sprintf("IP \\d+\\.\\d+\\.\\d+\\.\\d+\\.51820 > %s\\.51820: UDP", felix.IP)
				tcpdump.AddMatcher("numOutTunnelPackets", regexp.MustCompile(outTunnelPacketsPattern))

				tcpdump.Start()

				tcpdumps = append(tcpdumps, tcpdump)
			}
		})

		It("Wireguard supported nodes can communicate", func() {
			cc.ExpectSome(wls[0], wls[1])
			cc.ExpectSome(wls[1], wls[0])
			cc.CheckConnectivity()
		})

		It("Wireguard unsupported nodes don't send data over tunnel", func() {
			cc.ExpectSome(wls[0], wls[2])
			cc.ExpectSome(wls[2], wls[0])
			cc.CheckConnectivity()

			By("verifying tunnelled packet count")
			for i := range felixes {
				Eventually(tcpdumpMatchCount(i, "numInTunnelPackets")).Should(BeNumerically("==", 0))
				Eventually(tcpdumpMatchCount(i, "numOutTunnelPackets")).Should(BeNumerically("==", 0))
				fmt.Println("in-tunnel: ", (tcpdumpMatchCount(i, "numInTunnelPackets")()))
				fmt.Println("out-tunnel: ", (tcpdumpMatchCount(i, "numOutTunnelPackets")()))
			}
		})

		It("should allow felixes[0] to reach felixes[1] if ingress and egress policies are in place", func() {
			// Create a policy selecting felix[0] that allows egress.
			policy := api.NewGlobalNetworkPolicy()
			policy.Name = "f0-egress"
			policy.Spec.Egress = []api.Rule{{Action: api.Allow}}
			policy.Spec.Selector = fmt.Sprintf("hostname == '%s'", felixes[0].Hostname)
			_, err := client.GlobalNetworkPolicies().Create(utils.Ctx, policy, utils.NoOptions)
			Expect(err).NotTo(HaveOccurred())

			// Workload connectivity is unchanged.
			cc.ExpectSome(wls[0], wls[1])
			cc.ExpectSome(wls[1], wls[0])
			cc.CheckConnectivity()

			cc.ResetExpectations()

			// Now add a policy selecting felix[1] that allows ingress.
			policy = api.NewGlobalNetworkPolicy()
			policy.Name = "f1-ingress"
			policy.Spec.Ingress = []api.Rule{{Action: api.Allow}}
			policy.Spec.Selector = fmt.Sprintf("hostname == '%s'", felixes[1].Hostname)
			_, err = client.GlobalNetworkPolicies().Create(utils.Ctx, policy, utils.NoOptions)
			Expect(err).NotTo(HaveOccurred())

			// Workload connectivity is unchanged.
			cc.ExpectSome(wls[0], wls[1])
			cc.ExpectSome(wls[1], wls[0])
			cc.CheckConnectivity()
		})
	})
})

// Setup cluster toplogy options.
// mainly, enable Wireguard with delayed start option.
func wireguardTopologyOptions() infrastructure.TopologyOptions {
	topologyOptions := infrastructure.DefaultTopologyOptions()

	// Waiting for calico-node to be ready.
	topologyOptions.DelayFelixStart = true
	// Wireguard doesn't support IPv6, disable it.
	topologyOptions.EnableIPv6 = false
	// Assigning workload IPs using IPAM API.
	topologyOptions.IPIPRoutesEnabled = false

	// Enable Wireguard.
	felixConfig := api.NewFelixConfiguration()
	felixConfig.SetName("default")
	enabled := true
	felixConfig.Spec.WireguardEnabled = &enabled
	topologyOptions.InitialFelixConfiguration = felixConfig

	// Debugging.
	//topologyOptions.ExtraEnvVars["FELIX_DebugUseShortPollIntervals"] = "true"
	//topologyOptions.FelixLogSeverity = "debug"

	return topologyOptions
}

func enableWireguard(client clientv3.Interface) {
	updateWireguardEnabledConfig(client, true)
}

func disableWireguard(client clientv3.Interface) {
	updateWireguardEnabledConfig(client, false)
}

func disableWireguardForFelix(client clientv3.Interface, felixName string) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	felixConfig := api.NewFelixConfiguration()
	felixConfig.SetName(felixName)
	disabled := false
	felixConfig.Spec.WireguardEnabled = &disabled
	felixConfig, err := client.FelixConfigurations().Create(ctx, felixConfig, options.SetOptions{})
	Expect(err).NotTo(HaveOccurred())
}

func updateWireguardEnabledConfig(client clientv3.Interface, value bool) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	felixConfig, err := client.FelixConfigurations().Get(ctx, "default", options.GetOptions{})
	Expect(err).NotTo(HaveOccurred())
	felixConfig.Spec.WireguardEnabled = &value
	felixConfig, err = client.FelixConfigurations().Update(ctx, felixConfig, options.SetOptions{})
	Expect(err).NotTo(HaveOccurred())
}
