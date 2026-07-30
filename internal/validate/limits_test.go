package validate

import "testing"

// A repository sizes its result slice from the caller's limit before reading a single
// row, so an unbounded limit reserves memory for rows that may not exist: 50 million
// AdminUserRows is several gigabytes for a query that can return nothing. The list
// methods are exported, so the service's page_size clamp is not the only way in.
func TestPreallocateRowsCapsAtThePageSize(t *testing.T) {
	for _, testCase := range []struct {
		name  string
		limit int
		want  int
	}{
		{"typical page", 20, 20},
		{"exactly the cap", MaxPageSize, MaxPageSize},
		{"over the cap", MaxPageSize + 1, MaxPageSize},
		{"absurd", 50_000_000, MaxPageSize},
		{"max int", int(^uint(0) >> 1), MaxPageSize},
		// A non-positive limit is the repository's own argument error; reserving nothing
		// keeps make() from panicking on a negative capacity on the way there.
		{"zero", 0, 0},
		{"negative", -1, 0},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			if got := PreallocateRows(testCase.limit); got != testCase.want {
				t.Fatalf("PreallocateRows(%d) = %d, want %d", testCase.limit, got, testCase.want)
			}
		})
	}
}
