package k8sutils

import (
	"testing"

	"github.com/stretchr/testify/require"

	"k8s.io/api/core/v1"
)

var labelKeyTable = []struct {
	key   string
	valid bool
}{
	{"quay.io/singleTokenKey", true},
	{"singleTokenString", true},
	{"quay.io/double.TokenString", true},
	{"double.TokenString", true},
	{"triple.Token.String", true},
	{"quay.io/triple.Token.String", true},
	{"/empty.hostname", false},
	{"empty.keyname/", false},
	{"invalidKey_", false},
	{"_invalidKey", false},
	{"-invalidKey", false},
	{"invalidKey-", false},
	{"invalid--key", false},
	{"invalid__key", false},
	{"too/many/slashes", false},
	{"no:colons", false},
	{"ThisStringsLengthIs63oooooooooooooooooooooooooooooooooooooooooo", true},
	{"ThisStringsLengthIs64oooooooooooooooooooooooooooooooooooooooooo0", false},
	{"quay.io/ThisKeyNameLengthIs63oooooooooooooooooooooooooooooooooooooooooo", true},
	{"quay.io/ThisKeyNameLengthIs64oooooooooooooooooooooooooooooooooooooooooo0", false},
	{"", false},
}

var labelValueTable = []struct {
	value string
	valid bool
}{
	{"quay.io/singleTokenKey", false},
	{"singleTokenString", true},
	{"double.TokenString", true},
	{"triple.Token.String", true},
	{"/invalid.value", false},
	{"invalid.Value/", false},
	{"invalidValue_", false},
	{"_invalidValue", false},
	{"-invalidValue", false},
	{"invalidValue-", false},
	{"invalid--Value", false},
	{"invalid__Value", false},
	{"ThisStringsLengthIs63oooooooooooooooooooooooooooooooooooooooooo", true},
	{"ThisStringsLengthIs64oooooooooooooooooooooooooooooooooooooooooo0", false},
	{"", true},
}

func TestValidLabelKey(t *testing.T) {
	for _, tt := range labelKeyTable {
		validKey, _ := ValidLabelKey(tt.key)
		if validKey != tt.valid {
			t.Error("Incorrectly parsed key", tt.key, "as", validKey)
		}
	}
}

func TestValidLabelValue(t *testing.T) {
	for _, tt := range labelValueTable {
		validValue, _ := ValidLabelValue(tt.value)
		if validValue != tt.valid {
			t.Error("Incorrectly parsed value", tt.value, "as", validValue)
		}
	}
}

var deleteOldLabelTable = []struct {
	prefix         string
	oldLabels      map[string]string
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
			"TestKey1": "TestValue1",
			"TestKey2": "TestValue2",
			"TestKey3": "TestValue3",
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
			"TestKey1": "TestValue1",
			"TestKey2": "TestValue2",
			"TestKey3": "TestValue3",
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
			"TestPrefix/TestKey8": "TestValue8",
		},
	},
}

func TestPodDeleteOldLabelsWithPrefix(t *testing.T) {
	for _, tt := range deleteOldLabelTable {
		// Test pod
		var pod = &v1.Pod{}
		pod.ObjectMeta.Labels = make(map[string]string)

		// Add old labels to pod
		for k, v := range tt.oldLabels {
			pod.ObjectMeta.Labels[k] = v
		}

		PodDeleteOldLabelsWithPrefix(pod, tt.prefix, tt.newLabels)
		// A pod should:
		//   - Have the same number of labels as expectedLabels
		//   - Have the same corresponding keys with corresponding values as expectedLabels
		require.Equal(t, len(tt.expectedLabels), len(pod.ObjectMeta.Labels))
		for k, v := range pod.ObjectMeta.Labels {
			expectedVal, ok := tt.expectedLabels[k]
			if !ok || v != expectedVal {
				t.Error("Label with key", k, "and value", v, "not in expected labels")
			}
		}
	}
}
