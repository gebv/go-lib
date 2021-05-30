package errors

import (
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func Test_waitOneErrorOrNil_Wait(t *testing.T) {
	t.Run("happyPath-releaseNil", func(t *testing.T) {
		w := WaitOneErrorOrNil()

		errchan := make(chan error)
		go func() {
			errchan <- w.Wait()
		}()
		w.Release(nil)

		select {
		case got := <-errchan:
			assert.Nil(t, got)
		case <-time.After(time.Millisecond):
			t.Fatal("want error but not received error")
		}
	})
	t.Run("happyPath-WaitAndRelease", func(t *testing.T) {
		w := WaitOneErrorOrNil()

		err := errors.New("some error")

		errchan := make(chan error)
		go func() {
			errchan <- w.Wait()
		}()
		w.Release(err)

		select {
		case got := <-errchan:
			assert.Error(t, got)
			assert.EqualError(t, err, got.Error())
		case <-time.After(time.Millisecond):
			t.Fatal("want error but not received error")
		}
	})
	t.Run("happyPath-WaitAndRelease-multipleReleases", func(t *testing.T) {
		w := WaitOneErrorOrNil()

		err := errors.New("some error")

		errchan := make(chan error)
		go func() {
			errchan <- w.Wait()
		}()
		w.Release(err)

		select {
		case got := <-errchan:
			assert.Error(t, got)
			assert.EqualError(t, err, got.Error())
		case <-time.After(time.Millisecond):
			t.Fatal("want error but not received error")
		}
	})
	t.Run("happyPath-ReleaseAndWait", func(t *testing.T) {
		w := WaitOneErrorOrNil()

		err := errors.New("some error")

		w.Release(err)

		errchan := make(chan error)
		go func() {
			errchan <- w.Wait()
		}()

		select {
		case got := <-errchan:
			assert.Error(t, got)
			assert.EqualError(t, err, got.Error())
		case <-time.After(time.Millisecond):
			t.Fatal("want error but not received error")
		}
	})
	t.Run("happyPath-ReleaseAndWait-multipleRelease", func(t *testing.T) {
		w := WaitOneErrorOrNil()

		err := errors.New("some error")

		w.Release(err)
		w.Release(err)
		w.Release(err)
		w.Release(err)

		errchan := make(chan error)
		go func() {
			errchan <- w.Wait()
		}()

		select {
		case got := <-errchan:
			assert.Error(t, got)
			assert.EqualError(t, err, got.Error())
		case <-time.After(time.Millisecond):
			t.Fatal("want error but not received error")
		}
	})
	t.Run("noWait", func(t *testing.T) {
		w := WaitOneErrorOrNil()

		err := errors.New("some error")
		w.Release(err)
	})
	t.Run("noWait-multipleReleases", func(t *testing.T) {
		w := WaitOneErrorOrNil()

		err := errors.New("some error")
		w.Release(err)
		w.Release(err)
		w.Release(err)
		w.Release(err)
		w.Release(err)
	})
	t.Run("onlyWait", func(t *testing.T) {
		w := WaitOneErrorOrNil()

		errchan := make(chan error)
		go func() {
			errchan <- w.Wait()
		}()

		select {
		case got := <-errchan:
			t.Fatal("want no error but received error", got)
		case <-time.After(time.Millisecond):
		}
	})
	t.Run("onlyWait-multipleWaits", func(t *testing.T) {
		w := WaitOneErrorOrNil()

		errchan := make(chan error)
		go func() {
			errchan <- w.Wait()
		}()
		go func() {
			errchan <- w.Wait()
		}()
		go func() {
			errchan <- w.Wait()
		}()
		go func() {
			errchan <- w.Wait()
		}()

		select {
		case got := <-errchan:
			t.Fatal("want no error but received error", got)
		case <-time.After(time.Millisecond):
		}
	})
}
