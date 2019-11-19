package labeller

import (
	"fmt"
	"strings"
	"sync"

	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/watch"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/tools/cache"
)

var resourceVersionSeparator = ","

// Implements "k8s.io/client-go/tools/cache.ListerWatcher"
type multiListerWatcher []cache.ListerWatcher

func NewMultiNamespaceListerWatcher(namespaces []string, f func(string) cache.ListerWatcher) cache.ListerWatcher {
	if len(namespaces) == 0 {
		return f(corev1.NamespaceAll)
	}

	if len(namespaces) == 1 {
		return f(namespaces[0])
	}

	var lws []cache.ListerWatcher
	for _, ns := range namespaces {
		lws = append(lws, f(ns))
	}
	return multiListerWatcher(lws)
}

func (mlw multiListerWatcher) List(options metav1.ListOptions) (runtime.Object, error) {
	l := &metav1.List{}
	var resourceVersions []string
	for _, lw := range mlw {
		list, err := lw.List(options)
		if err != nil {
			return nil, err
		}
		items, err := meta.ExtractList(list)
		if err != nil {
			return nil, err
		}
		metaObj, err := meta.ListAccessor(list)
		if err != nil {
			return nil, err
		}
		for _, item := range items {
			l.Items = append(l.Items, runtime.RawExtension{Object: item.DeepCopyObject()})
		}
		resourceVersions = append(resourceVersions, metaObj.GetResourceVersion())
	}
	l.ListMeta.ResourceVersion = strings.Join(resourceVersions, resourceVersionSeparator)
	return l, nil
}

func (mlw multiListerWatcher) Watch(options metav1.ListOptions) (watch.Interface, error) {
	var resourceVersions []string
	if options.ResourceVersion != "" {
		listResourceVersions := strings.Split(options.ResourceVersion, resourceVersionSeparator)
		if len(listResourceVersions) != len(mlw) {
			return nil, fmt.Errorf("Number of resource versions(%d) does not match number of ListerWatcher(%d)", len(listResourceVersions), len(mlw))
		}
		resourceVersions = listResourceVersions
	}
	return newMultiWatch(mlw, resourceVersions, options)
}

// Implements "k8s.io/apimachinery/pkg/watch.Interface"
type multiWatch struct {
	events   chan watch.Event
	stopped  chan struct{}
	stoppers []func()
}

func newMultiWatch(lws []cache.ListerWatcher, resourceVersions []string, options metav1.ListOptions) (*multiWatch, error) {
	var (
		events   = make(chan watch.Event)
		stopped  = make(chan struct{})
		stoppers []func()
		wg       sync.WaitGroup
	)

	wg.Add(len(lws))

	for i, lw := range lws {
		options := options.DeepCopy()
		options.ResourceVersion = resourceVersions[i]
		w, err := lw.Watch(*options)
		if err != nil {
			return nil, err
		}

		go func() {
			defer wg.Done()

			for {
				event, ok := <-w.ResultChan()
				if !ok {
					return
				}

				select {
				case events <- event:
				case <-stopped:
					return
				}
			}
		}()
		stoppers = append(stoppers, w.Stop)
	}

	go func() {
		wg.Wait()
		close(events)
	}()

	return &multiWatch{
		events:   events,
		stoppers: stoppers,
		stopped:  stopped,
	}, nil
}

func (mw *multiWatch) Stop() {
	select {
	case <-mw.stopped:
	default:
		for _, stop := range mw.stoppers {
			stop()
		}
		close(mw.stopped)
	}
}

func (mw *multiWatch) ResultChan() <-chan watch.Event {
	return mw.events
}
