package labeller

import (
	"reflect"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/quay/container-security-operator/k8sutils"
	"k8s.io/api/core/v1"
)

var podLabelsTable = []struct {
	prefix         string
	initialLabels  map[string]string
	newLabels      map[string]string
	expectedLabels map[string]string
}{
	{
		// newLabels is a subset of oldLabels
		"TestPrefix",
		map[string]string{
			"TestKey1":            "TestValue1",
			"TestKey2":            "TestValue2",
			"TestKey3":            "TestValue3",
			"TestPrefix/TestKey4": "TestValue4",
			"TestPrefix/TestKey5": "TestValue5",
			"TestPrefix/TestKey6": "TestValue6",
		},
		map[string]string{
			"TestPrefix/TestKey5": "TestValue5",
		},
		map[string]string{
			"TestKey1":            "TestValue1",
			"TestKey2":            "TestValue2",
			"TestKey3":            "TestValue3",
			"TestPrefix/TestKey5": "TestValue5",
		},
	},
	{
		// newLabels is a superset of oldLabels
		"TestPrefix",
		map[string]string{
			"TestKey1":            "TestValue1",
			"TestKey2":            "TestValue2",
			"TestKey3":            "TestValue3",
			"TestPrefix/TestKey4": "TestValue4",
		},
		map[string]string{
			"TestPrefix/TestKey4": "TestValue4",
			"TestPrefix/TestKey5": "TestValue5",
			"TestPrefix/TestKey6": "TestValue6",
		},
		map[string]string{
			"TestKey1":            "TestValue1",
			"TestKey2":            "TestValue2",
			"TestKey3":            "TestValue3",
			"TestPrefix/TestKey4": "TestValue4",
			"TestPrefix/TestKey5": "TestValue5",
			"TestPrefix/TestKey6": "TestValue6",
		},
	},
	{
		// newLabels has corresponding keys with different values
		"TestPrefix",
		map[string]string{
			"TestKey1":            "TestValue1",
			"TestKey2":            "TestValue2",
			"TestKey3":            "TestValue3",
			"TestPrefix/TestKey4": "TestValue4",
			"TestPrefix/TestKey5": "TestValue5",
		},
		map[string]string{
			"TestPrefix/TestKey4": "TestValue6",
			"TestPrefix/TestKey5": "TestValue7",
		},
		map[string]string{
			"TestKey1":            "TestValue1",
			"TestKey2":            "TestValue2",
			"TestKey3":            "TestValue3",
			"TestPrefix/TestKey4": "TestValue6",
			"TestPrefix/TestKey5": "TestValue7",
		},
	},
	{
		"TestPrefix",
		map[string]string{
			"TestKey1":            "TestValue1",
			"TestKey2":            "TestValue2",
			"TestKey3":            "TestValue3",
			"TestPrefix/TestKey4": "TestValue4",
			"TestPrefix/TestKey5": "TestValue5",
			"TestPrefix/TestKey8": "TestValue8",
		},
		map[string]string{
			"TestPrefix/TestKey4": "TestValue6",
			"TestPrefix/TestKey5": "TestValue7",
		},
		map[string]string{
			"TestKey1":            "TestValue1",
			"TestKey2":            "TestValue2",
			"TestKey3":            "TestValue3",
			"TestPrefix/TestKey4": "TestValue6",
			"TestPrefix/TestKey5": "TestValue7",
		},
	},
	{
		"TestPrefix",
		map[string]string{
			"TestKey1":            "TestValue1",
			"TestKey2":            "TestValue2",
			"TestKey3":            "TestValue3",
			"TestPrefix/TestKey4": "TestValue4",
			"TestPrefix/TestKey5": "TestValue5",
			"TestPrefix/TestKey8": "TestValue8",
		},
		map[string]string{
			"TestPrefix/TestKey4": "TestValue6",
			"TestPrefix/TestKey5": "TestValue7",
			"TestPrefix/TestKey8": "TestValue8",
		},
		map[string]string{
			"TestKey1":            "TestValue1",
			"TestKey2":            "TestValue2",
			"TestKey3":            "TestValue3",
			"TestPrefix/TestKey4": "TestValue6",
			"TestPrefix/TestKey5": "TestValue7",
			"TestPrefix/TestKey8": "TestValue8",
		},
	},
}

func TestLabelPod(t *testing.T) {
	for _, tt := range podLabelsTable {
		pod := generatePodWithLabels(tt.initialLabels)
		k8sutils.PodAddOrUpdateLabels(pod, tt.newLabels)
		k8sutils.PodDeleteOldLabelsWithPrefix(pod, tt.prefix, tt.newLabels)

		require.True(t, reflect.DeepEqual(pod.ObjectMeta.Labels, tt.expectedLabels))
	}
}

func generatePodWithLabels(initialLabels map[string]string) *v1.Pod {
	pod := &v1.Pod{}
	pod.ObjectMeta.Labels = make(map[string]string)
	for k, v := range initialLabels {
		pod.ObjectMeta.Labels[k] = v
	}
	return pod
}

var addVulnerabilitycountLabelsTable = []struct {
	expected map[string]string
	pValues  map[string]int
}{
	{map[string]string{},
		map[string]int{"P0": 0, "P0Fixable": 0, "P1": 0, "P1Fixable": 0, "P2": 0, "P2Fixable": 0, "P3": 0, "P3Fixable": 0}},

	{map[string]string{"prefix/P0": "1", "prefix/highest": "P0"},
		map[string]int{"P0": 1, "P0Fixable": 0, "P1": 0, "P1Fixable": 0, "P2": 0, "P2Fixable": 0, "P3": 0, "P3Fixable": 0}},

	{map[string]string{"prefix/P0Fixables": "1", "prefix/fixables": "1"},
		map[string]int{"P0": 0, "P0Fixable": 1, "P1": 0, "P1Fixable": 0, "P2": 0, "P2Fixable": 0, "P3": 0, "P3Fixable": 0}},

	{map[string]string{"prefix/P1": "1", "prefix/highest": "P1"},
		map[string]int{"P0": 0, "P0Fixable": 0, "P1": 1, "P1Fixable": 0, "P2": 0, "P2Fixable": 0, "P3": 0, "P3Fixable": 0}},

	{map[string]string{"prefix/P1Fixables": "1", "prefix/fixables": "1"},
		map[string]int{"P0": 0, "P0Fixable": 0, "P1": 0, "P1Fixable": 1, "P2": 0, "P2Fixable": 0, "P3": 0, "P3Fixable": 0}},

	{map[string]string{"prefix/P2": "1", "prefix/highest": "P2"},
		map[string]int{"P0": 0, "P0Fixable": 0, "P1": 0, "P1Fixable": 0, "P2": 1, "P2Fixable": 0, "P3": 0, "P3Fixable": 0}},

	{map[string]string{"prefix/P2Fixables": "1", "prefix/fixables": "1"},
		map[string]int{"P0": 0, "P0Fixable": 0, "P1": 0, "P1Fixable": 0, "P2": 0, "P2Fixable": 1, "P3": 0, "P3Fixable": 0}},

	{map[string]string{"prefix/P3": "1", "prefix/highest": "P3"},
		map[string]int{"P0": 0, "P0Fixable": 0, "P1": 0, "P1Fixable": 0, "P2": 0, "P2Fixable": 0, "P3": 1, "P3Fixable": 0}},

	{map[string]string{"prefix/P3Fixables": "1", "prefix/fixables": "1"},
		map[string]int{"P0": 0, "P0Fixable": 0, "P1": 0, "P1Fixable": 0, "P2": 0, "P2Fixable": 0, "P3": 0, "P3Fixable": 1}},

	{map[string]string{"prefix/P3": "1", "prefix/P2Fixables": "1", "prefix/P3Fixables": "1", "prefix/fixables": "4", "prefix/P0": "1", "prefix/P1": "1", "prefix/P2": "1", "prefix/P0Fixables": "1", "prefix/P1Fixables": "1", "prefix/highest": "P0"},
		map[string]int{"P0": 1, "P0Fixable": 1, "P1": 1, "P1Fixable": 1, "P2": 1, "P2Fixable": 1, "P3": 1, "P3Fixable": 1}},
}

func TestAddVulnerabilityCountLabels(t *testing.T) {
	for _, tc := range addVulnerabilitycountLabelsTable {
		podVulnerabilityCount := PodVulnerabilityCount{
			P0: tc.pValues["P0"], P0Fixable: tc.pValues["P0Fixable"],
			P1: tc.pValues["P1"], P1Fixable: tc.pValues["P1Fixable"],
			P2: tc.pValues["P2"], P2Fixable: tc.pValues["P2Fixable"],
			P3: tc.pValues["P3"], P3Fixable: tc.pValues["P3Fixable"]}

		sut := Labeller{labelPrefix: "prefix"}
		actual := sut.addVulnerabilityCountLabels(&podVulnerabilityCount)
		require.Equal(t, tc.expected, actual)
	}
}
