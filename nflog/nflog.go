package nflog

import (
	"bytes"
	"errors"
	"io"
	"sync"
	"time"

	"github.com/golang/protobuf/ptypes"
	"github.com/matttproud/golang_protobuf_extensions/pbutil"
	pb "github.com/prometheus/alertmanager/nflog/nflogpb"
	"github.com/weaveworks/mesh"
)

// Log stores and serves information about notifications
// about byte-slice addressed alert objects to different receivers.
type Log interface {
	// The Log* methods store a notification log entry for
	// a fully qualified receiver and a given IDs identifying the
	// alert object.
	LogActive(r *pb.Receiver, key, hash []byte) error
	LogResolved(r *pb.Receiver, key, hash []byte) error

	// Query the log along the given Paramteres.
	Query(p ...QueryParam) ([]*Entry, error)
	// Delete log entries along the given Parameters. Returns
	// the number of deleted entries.
	Delete(p ...DeleteParam) (int, error)

	// Snapshot the current log state and return the number
	// of bytes written.
	Snapshot(w io.Writer) (int, error)
}

// query currently allows filtering by and/or receiver group key.
// It is configured via QueryParameter functions.
//
// TODO(fabxc): Future versions could allow querying a certain receiver
// group or a given time interval.
type query struct {
	recv     *Receiver
	groupKey []byte
}

// QueryParam is a function that modifies a query to incorporate
// a set of parameters. Returns an error for invalid or conflicting
// parameters.
type QueryParam func(*query) error

// QReceiver adds a receiver parameter to a query.
func QReceiver(r *Receiver) QueryParam {
	return func(q *query) error {
		q.recv = r
		return nil
	}
}

// QGroupKey adds a group key as querying argument.
func QGroupKey(gk []byte) QueryParam {
	return func(q *query) error {
		q.groupKey = gk
		return nil
	}
}

// delete holds parameters for a deletion query.
type delete struct {
	// Delete log entries that are expired. Does NOT delete
	// unexpired entries if set to false.
	expired bool
}

// DeleteParam is a function that modifies parameters of a delete request.
// Returns an error for invalid of conflicting parameters.
type DeleteParam func(*delete) error

// DExpired adds a parameter to delete expired log entries.
func DExpired() DeleteParam {
	return func(d *delete) error {
		d.expired = true
		return nil
	}
}

type nlog struct {
	retention time.Duration
	now       func() time.Time

	mtx     sync.RWMutex
	entries []*pb.MeshEntry
}

// Option configures a new Log implementation.
type Option func(*nlog) error

// WithMesh registers the log with a mesh network with which
// the log state will be shared.
func WithMesh(mr *mesh.Router) Option {
	return func(l *nlog) {
		panic("not implemented")
	}
}

// WithRetention sets the retention time for log entries.
func WithRetention(d time.Duration) Option {
	return func(l *nlog) {
		l.retention = d
	}
}

// WithNow overwrites the function used to retrieve a timestamp
// for the current point in time.
// This is generally useful for injection during tests.
func WithNow(f func() time.Time) Option {
	return func(l *nlog) {
		l.now = f
	}
}

// New creates a new notification log based on the provided options.
// The snapshot is loaded into the Log if it is set.
func New(snapshot io.Reader, opts ...Option) (Log, error) {
	l := &nlog{
		l.now: time.Now,
	}
	for _, o := range opts {
		if err := o(l); err != nil {
			return nil, err
		}
	}
	if snapshot != nil {
		if err := l.loadSnapshot(snapshot); err != nil {
			return l, err
		}
	}
	return l, nil
}

// LogActive implements the Log interface.
func (l *nlog) LogActive(r *pb.Receiver, key, hash []byte) error {
	return l.log(r, false, ids...)
}

// LogResolved implements the Log interface.
func (l *nlog) LogResolved(r *pb.Receiver, key, hash []byte) error {
	return l.log(r, true, ids...)
}

func (l *nlog) log(r *pb.Receiver, resolved bool, key, hash []byte) error {
	// Write all entries with the same timestamp.
	now := l.now()

	ts, err := ptypes.TimestampProto(now)
	if err != nil {
		return err
	}
	expts, err := ptypes.TimestampProto(now.Add(l.retention))
	if err != nil {
		return err
	}

	le := pb.Entry{
		Receiver:  r,
		GroupKey:  key,
		GroupHash: hash,
		Resolved:  resolved,
		Timestamp: ts,
	}
	l.entries = append(l.entries, &pb.MeshEntry{
		Entry:     &le,
		ExpiresAt: expts,
	})
	return nil
}

// Delete implements the Log interface.
func (l *nlog) Delete(params ...DeleteParam) (int, error) {
	l.mtx.Lock()
	defer l.mtx.Unlock()

	var del delete
	for _, p := range params {
		if err := p(&del); err != nil {
			return 0, err
		}
	}
	if !del.expired {
		return 0, errors.New("only expiration deletion supported")
	}

	var repl []*pb.MeshEntry
	now := l.now()

	for _, e := range l.entries {
		ets, err := ptypes.Timestamp(e.ExpiresAt)
		if err != nil {
			return nil, err
		}
		if !ets.Before(now) {
			repl = append(repl, e)
		}
	}
	n := len(l.entries) - len(repl)
	l.entries = repl

	return n, nil
}

// Query implements the Log interface.
func (l *nlog) Query(params ...QueryParam) ([]*pb.Entry, error) {
	q := &query{}
	for _, p := range params {
		if err := p(q); err != nil {
			return nil, err
		}
	}
	if q.recv == nil || q.groupKey == nil {
		// TODO(fabxc): allow more complex queries in the future.
		// How to enable pagination?
		return errors.New("no query parameters specified")
	}

	l.mtx.RLock()
	defer l.mtx.RUnlock()

	for _, e := range l.entries {
		// Do the cheaper check first.
		if !bytes.Equal(e.Entry.GroupKey, q.groupKey) {
			continue
		}
		if *e.Entry.Receiver != *q.recv {
			continue
		}
		// Also return expired entries for now.
		//
		// TODO(fabxc): Is this semantically okay?
		// The cost of checking each entry when we
		// collect garbage periodically seems high for virtually no benefit.

		// By default return the most recent entry.
		//
		// TODO(fabxc): can be extended by a QTimeRange option
		// to show information on historic notifications for a group.

		// For now our only query mode is the most recent entry for a
		// receiver/group_key combination. As we insert append only to a slice,
		// we take the first result.
		// This means iterating the whole slice if there's no match.
		return []*pb.Entry{e.Entry}, nil
	}

	return nil, errors.New("no log entry found")
}

func (l *nlog) loadSnapshot(r io.Reader) error {
	l.mtx.Lock()
	defer l.mtx.Unlock()

	l.entries = l.entries[:0]

	for {
		var e pb.MeshEntry
		if _, err := pbutil.ReadDelimited(r, &e); err != nil {
			if err == io.EOF {
				break
			}
			return err
		}
		l.entries = append(l.entries, e)
	}

	return nil
}

// Snapshot implements the Log interface.
func (l *nlog) Snapshot(w io.Writer) (int, error) {
	l.mtx.RLock()
	defer l.mtx.RUnlock()

	var n int
	for _, e := range l.entries {
		m, err := pbutil.WriteDelimited(w, e)
		if err != nil {
			return n + m, err
		}
		n += m
	}
	return n, nil
}
