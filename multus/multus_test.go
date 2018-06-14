// Copyright (c) 2017 Intel Corporation
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
//

package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/containernetworking/cni/pkg/skel"
	cnitypes "github.com/containernetworking/cni/pkg/types"
	"github.com/containernetworking/cni/pkg/types/020"
	"github.com/containernetworking/cni/pkg/version"
	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/containernetworking/plugins/pkg/testutils"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	v1 "k8s.io/client-go/pkg/api/v1"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

func TestMultus(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "multus")
}

type fakePlugin struct {
	expectedEnv  []string
	expectedConf string
	result       cnitypes.Result
	err          error
}

type fakeExec struct {
	version.PluginDecoder

	addIndex int
	delIndex int
	plugins  []*fakePlugin
}

func (f *fakeExec) addPlugin(expectedEnv []string, expectedConf string, result *types020.Result, err error) {
	f.plugins = append(f.plugins, &fakePlugin{
		expectedEnv:  expectedEnv,
		expectedConf: expectedConf,
		result:       result,
		err:          err,
	})
}

func matchArray(a1, a2 []string) {
	Expect(len(a1)).To(Equal(len(a2)))
	for _, e1 := range a1 {
		found := ""
		for _, e2 := range a2 {
			if e1 == e2 {
				found = e2
				break
			}
		}
		// Compare element values for more descriptive test failure
		Expect(e1).To(Equal(found))
	}
}

func (f *fakeExec) ExecPlugin(pluginPath string, stdinData []byte, environ []string) ([]byte, error) {
	cmd := os.Getenv("CNI_COMMAND")
	var index int
	switch cmd {
	case "ADD":
		Expect(len(f.plugins)).To(BeNumerically(">", f.addIndex))
		index = f.addIndex
		f.addIndex++
	case "DEL":
		Expect(len(f.plugins)).To(BeNumerically(">", f.delIndex))
		// +1 to skip loopback since it isn't run on DEL
		index = f.delIndex + 1
		f.delIndex++
	default:
		// Should never be reached
		Expect(false).To(BeTrue())
	}
	plugin := f.plugins[index]

	GinkgoT().Logf("[%s %d] exec plugin %q found %+v\n", cmd, index, pluginPath, plugin)

	if plugin.expectedConf != "" {
		Expect(string(stdinData)).To(MatchJSON(plugin.expectedConf))
	}
	if len(plugin.expectedEnv) > 0 {
		matchArray(environ, plugin.expectedEnv)
	}

	if plugin.err != nil {
		return nil, plugin.err
	}

	resultJSON, err := json.Marshal(plugin.result)
	Expect(err).NotTo(HaveOccurred())
	return resultJSON, nil
}

func (f *fakeExec) FindInPath(plugin string, paths []string) (string, error) {
	Expect(len(paths)).To(BeNumerically(">", 0))
	return filepath.Join(paths[0], plugin), nil
}

type fakeKubeClient struct {
	pods     map[string]*v1.Pod
	podCount int
	nets     map[string]string
	netCount int
}

func newFakeKubeClient() *fakeKubeClient {
	return &fakeKubeClient{
		pods: make(map[string]*v1.Pod),
		nets: make(map[string]string),
	}
}

func (f *fakeKubeClient) GetRawWithPath(path string) ([]byte, error) {
	obj, ok := f.nets[path]
	if !ok {
		return nil, fmt.Errorf("resource not found")
	}
	f.netCount++
	return []byte(obj), nil
}

func (f *fakeKubeClient) addNet(namespace, name, data string) {
	cr := fmt.Sprintf(`{
  "apiVersion": "kubernetes.cni.cncf.io/v1",
  "kind": "Network",
  "metadata": {
    "namespace": "%s",
    "name": "%s"
  },
  "spec": {
    "config": "%s"
  }
}`, namespace, name, strings.Replace(data, "\"", "\\\"", -1))
	cr = strings.Replace(cr, "\n", "", -1)
	cr = strings.Replace(cr, "\t", "", -1)
	f.nets[fmt.Sprintf("/apis/kubernetes.cni.cncf.io/v1/namespaces/%s/networks/%s", namespace, name)] = cr
}

func (f *fakeKubeClient) GetPod(namespace, name string) (*v1.Pod, error) {
	key := fmt.Sprintf("%s/%s", namespace, name)
	pod, ok := f.pods[key]
	if !ok {
		return nil, fmt.Errorf("pod not found")
	}
	f.podCount++
	return pod, nil
}

func (f *fakeKubeClient) addPod(pod *v1.Pod) {
	key := fmt.Sprintf("%s/%s", pod.ObjectMeta.Namespace, pod.ObjectMeta.Name)
	f.pods[key] = pod
}

func ensureCIDR(cidr string) *net.IPNet {
	ip, net, err := net.ParseCIDR(cidr)
	Expect(err).NotTo(HaveOccurred())
	net.IP = ip
	return net
}

func newFakePod(name string, annotations map[string]string) *v1.Pod {
	return &v1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:        name,
			Namespace:   "test",
			Annotations: annotations,
		},
		Spec: v1.PodSpec{
			Containers: []v1.Container{
				{Name: "ctr1", Image: "image"},
			},
		},
	}
}

var _ = Describe("multus operations", func() {
	var testNS ns.NetNS
	var tmpDir string

	BeforeEach(func() {
		// Create a new NetNS so we don't modify the host
		var err error
		testNS, err = testutils.NewNS()
		Expect(err).NotTo(HaveOccurred())
		os.Setenv("CNI_NETNS", testNS.Path())
		os.Setenv("CNI_PATH", "/some/path")

		tmpDir, err = ioutil.TempDir("", "multus_tmp")
		Expect(err).NotTo(HaveOccurred())
	})

	AfterEach(func() {
		Expect(testNS.Close()).To(Succeed())
		os.Unsetenv("CNI_PATH")
		os.Unsetenv("CNI_ARGS")
		err := os.RemoveAll(tmpDir)
		Expect(err).NotTo(HaveOccurred())
	})

	It("executes delegates", func() {
		args := &skel.CmdArgs{
			ContainerID: "123456789",
			Netns:       testNS.Path(),
			IfName:      "eth0",
			StdinData: []byte(`{
    "name": "node-cni-network",
    "type": "multus",
    "delegates": [{
        "name": "weave1",
        "cniVersion": "0.2.0",
        "type": "weave-net"
    },{
        "name": "other1",
        "cniVersion": "0.2.0",
        "type": "other-plugin"
    }]
}`),
		}

		fExec := &fakeExec{}
		expectedResult1 := &types020.Result{
			CNIVersion: "0.2.0",
			IP4: &types020.IPConfig{
				IP: *ensureCIDR("1.1.1.2/24"),
			},
		}
		expectedConf1 := `{
    "name": "weave1",
    "cniVersion": "0.2.0",
    "type": "weave-net"
}`
		fExec.addPlugin(nil, expectedConf1, expectedResult1, nil)

		expectedResult2 := &types020.Result{
			CNIVersion: "0.2.0",
			IP4: &types020.IPConfig{
				IP: *ensureCIDR("1.1.1.5/24"),
			},
		}
		expectedConf2 := `{
    "name": "other1",
    "cniVersion": "0.2.0",
    "type": "other-plugin"
}`
		fExec.addPlugin(nil, expectedConf2, expectedResult2, nil)

		os.Setenv("CNI_COMMAND", "ADD")
		os.Setenv("CNI_IFNAME", "eth0")
		result, err := cmdAdd(args, fExec, nil)
		Expect(err).NotTo(HaveOccurred())
		Expect(fExec.addIndex).To(Equal(len(fExec.plugins)))
		r := result.(*types020.Result)
		// plugin 1 is the masterplugin
		Expect(reflect.DeepEqual(r, expectedResult1)).To(BeTrue())
	})

	It("executes delegates and kubernetes networks", func() {
		fakePod := newFakePod("testpod", map[string]string{
			"kubernetes.v1.cni.cncf.io/networks": "net1,net2",
		})
		net1 := `{
	"name": "net1",
	"type": "mynet",
	"cniVersion": "0.2.0"
}`
		net2 := `{
	"name": "net2",
	"type": "mynet2",
	"cniVersion": "0.2.0"
}`
		net3 := `{
	"name": "net3",
	"type": "mynet3",
	"cniVersion": "0.2.0"
}`
		args := &skel.CmdArgs{
			ContainerID: "123456789",
			Netns:       testNS.Path(),
			IfName:      "eth0",
			Args:        fmt.Sprintf("K8S_POD_NAME=%s;K8S_POD_NAMESPACE=%s", fakePod.ObjectMeta.Name, fakePod.ObjectMeta.Namespace),
			StdinData: []byte(`{
    "name": "node-cni-network",
    "type": "multus",
    "kubeconfig": "/etc/kubernetes/node-kubeconfig.yaml",
    "delegates": [{
        "name": "weave1",
        "cniVersion": "0.2.0",
        "type": "weave-net"
    }]
}`),
		}

		fExec := &fakeExec{}
		expectedResult1 := &types020.Result{
			CNIVersion: "0.2.0",
			IP4: &types020.IPConfig{
				IP: *ensureCIDR("1.1.1.2/24"),
			},
		}
		expectedConf1 := `{
    "name": "weave1",
    "cniVersion": "0.2.0",
    "type": "weave-net"
}`
		fExec.addPlugin(nil, expectedConf1, expectedResult1, nil)
		fExec.addPlugin(nil, net1, &types020.Result{
			CNIVersion: "0.2.0",
			IP4: &types020.IPConfig{
				IP: *ensureCIDR("1.1.1.3/24"),
			},
		}, nil)
		fExec.addPlugin(nil, net2, &types020.Result{
			CNIVersion: "0.2.0",
			IP4: &types020.IPConfig{
				IP: *ensureCIDR("1.1.1.4/24"),
			},
		}, nil)

		fKubeClient := newFakeKubeClient()
		fKubeClient.addPod(fakePod)
		fKubeClient.addNet(fakePod.ObjectMeta.Namespace, "net1", net1)
		fKubeClient.addNet(fakePod.ObjectMeta.Namespace, "net2", net2)
		// net3 is not used; make sure it's not accessed
		fKubeClient.addNet(fakePod.ObjectMeta.Namespace, "net3", net3)

		os.Setenv("CNI_COMMAND", "ADD")
		os.Setenv("CNI_IFNAME", "eth0")
		result, err := cmdAdd(args, fExec, fKubeClient)
		Expect(err).NotTo(HaveOccurred())
		Expect(fExec.addIndex).To(Equal(len(fExec.plugins)))
		Expect(fKubeClient.podCount).To(Equal(1))
		Expect(fKubeClient.netCount).To(Equal(2))
		r := result.(*types020.Result)
		// plugin 1 is the masterplugin
		Expect(reflect.DeepEqual(r, expectedResult1)).To(BeFalse())
	})
})
