package boottime

import (
	"testing"
	"time"
)

func TestFloorParses(t *testing.T) {
	if Floor().IsZero() {
		t.Fatal("default build floor must parse to a non-zero time")
	}
}

func TestClampFallsBackToFloor(t *testing.T) {
	floor := Floor()

	t.Run("failed read", func(t *testing.T) {
		if got := clamp(time.Now(), false); !got.Equal(floor) {
			t.Errorf("want floor, got %v", got)
		}
	})

	t.Run("reading before floor", func(t *testing.T) {
		early := floor.Add(-time.Hour)
		if got := clamp(early, true); !got.Equal(floor) {
			t.Errorf("want floor, got %v", got)
		}
	})

	t.Run("reading after floor is kept", func(t *testing.T) {
		later := floor.Add(time.Hour)
		if got := clamp(later, true); !got.Equal(later) {
			t.Errorf("want %v, got %v", later, got)
		}
	})
}

func TestHostNowIsFloor(t *testing.T) {
	if !Now().Equal(Floor()) {
		t.Error("host Now must equal the floor for deterministic tests")
	}
}
