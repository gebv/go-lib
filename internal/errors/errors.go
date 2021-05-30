package errors

import (
	"context"
	"sync"
)

// code based on https://github.com/golang/sync/blob/master/errgroup/errgroup.go

func WaitOneErrorOrNil() *waitOneErrorOrNil {
	w := &waitOneErrorOrNil{}
	w.wg.Add(1)
	return w
}

func WaitOneErrorOrNilWithontext(ctx context.Context) (*waitOneErrorOrNil, context.Context) {
	ctx, cancel := context.WithCancel(ctx)
	w := &waitOneErrorOrNil{cancel: cancel}
	w.wg.Add(1)
	return w, ctx
}

type waitOneErrorOrNil struct {
	cancel  context.CancelFunc
	wg      sync.WaitGroup
	errOnce sync.Once
	err     error
}

func (g *waitOneErrorOrNil) Wait() error {
	g.wg.Wait()

	if g.cancel != nil {
		g.cancel()
	}
	return g.err
}

func (g *waitOneErrorOrNil) Release(err error) {
	g.errOnce.Do(func() {
		defer g.wg.Done()

		g.err = err
		if g.cancel != nil {
			g.cancel()
		}
	})
}
