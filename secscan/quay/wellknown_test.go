package quay

import "testing"

type FakeWellknown struct {
}

func (f *FakeWellknown) AppCapabilities() {
	return
}

func TestGetAppCapabilities(t *testing.T) {

}
