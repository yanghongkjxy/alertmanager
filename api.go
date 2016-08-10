// Copyright 2015 Prometheus Team
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/common/log"
	"github.com/prometheus/common/model"
	"github.com/prometheus/common/route"
	"github.com/prometheus/common/version"
	"golang.org/x/net/context"

	"github.com/prometheus/alertmanager/provider"
	"github.com/prometheus/alertmanager/types"
)

var (
	numReceivedAlerts = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "alertmanager",
		Name:      "alerts_received_total",
		Help:      "The total number of received alerts.",
	}, []string{"status"})

	numInvalidAlerts = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "alertmanager",
		Name:      "alerts_invalid_total",
		Help:      "The total number of received alerts that were invalid.",
	})
)

func init() {
	prometheus.Register(numReceivedAlerts)
	prometheus.Register(numInvalidAlerts)
}

// API provides registration of handlers for API routes.
type API struct {
	alerts         provider.Alerts
	silences       provider.Silences
	config         string
	resolveTimeout time.Duration
	uptime         time.Time

	groups func() AlertOverview

	// context is an indirection for testing.
	context func(r *http.Request) context.Context
	mtx     sync.RWMutex
}

// NewAPI returns a new API.
func NewAPI(alerts provider.Alerts, silences provider.Silences, gf func() AlertOverview) *API {
	return &API{
		context:  route.Context,
		alerts:   alerts,
		silences: silences,
		groups:   gf,
		uptime:   time.Now(),
	}
}

// Register registers the API handlers under their correct routes
// in the given router.
func (api *API) Register(r *route.Router) {
	ihf := prometheus.InstrumentHandlerFunc

	// Register legacy forwarder for alert pushing.
	r.Post("/alerts", ihf("legacy_add_alerts", api.legacyAddAlerts))

	// Register actual API.
	r = r.WithPrefix("/v1")

	r.Get("/status", ihf("status", api.status))
	r.Get("/alerts/groups", ihf("alert_groups", api.alertGroups))

	r.Get("/alerts", ihf("list_alerts", api.listAlerts))
	r.Post("/alerts", ihf("add_alerts", api.addAlerts))

	r.Get("/silences", ihf("list_silences", api.listSilences))
	r.Post("/silences", ihf("add_silence", api.addSilence))
	r.Get("/silence/:sid", ihf("get_silence", api.getSilence))
	r.Del("/silence/:sid", ihf("del_silence", api.delSilence))
}

// Update sets the configuration string to a new value.
func (api *API) Update(config string, resolveTimeout time.Duration) {
	api.mtx.Lock()
	defer api.mtx.Unlock()

	api.config = config
	api.resolveTimeout = resolveTimeout
}

type errorType string

const (
	errorNone     errorType = ""
	errorInternal           = "server_error"
	errorBadData            = "bad_data"
)

type apiError struct {
	typ errorType
	err error
}

func (e *apiError) Error() string {
	return fmt.Sprintf("%s: %s", e.typ, e.err)
}

func (api *API) status(w http.ResponseWriter, req *http.Request) {
	api.mtx.RLock()

	var status = struct {
		Config      string            `json:"config"`
		VersionInfo map[string]string `json:"versionInfo"`
		Uptime      time.Time         `json:"uptime"`
	}{
		Config: api.config,
		VersionInfo: map[string]string{
			"version":   version.Version,
			"revision":  version.Revision,
			"branch":    version.Branch,
			"buildUser": version.BuildUser,
			"buildDate": version.BuildDate,
			"goVersion": version.GoVersion,
		},
		Uptime: api.uptime,
	}

	api.mtx.RUnlock()

	respond(w, status)
}

func (api *API) alertGroups(w http.ResponseWriter, req *http.Request) {
	respond(w, api.groups())
}

func (api *API) listAlerts(w http.ResponseWriter, r *http.Request) {
	alerts := api.alerts.GetPending()
	defer alerts.Close()

	var (
		err error
		res []*types.Alert
	)
	// TODO(fabxc): enforce a sensible timeout.
	for a := range alerts.Next() {
		if err = alerts.Err(); err != nil {
			break
		}
		res = append(res, a)
	}

	if err != nil {
		respondError(w, apiError{
			typ: errorInternal,
			err: err,
		}, nil)
		return
	}
	respond(w, types.Alerts(res...))
}

func (api *API) legacyAddAlerts(w http.ResponseWriter, r *http.Request) {
	var legacyAlerts = []struct {
		Summary     model.LabelValue `json:"summary"`
		Description model.LabelValue `json:"description"`
		Runbook     model.LabelValue `json:"runbook"`
		Labels      model.LabelSet   `json:"labels"`
		Payload     model.LabelSet   `json:"payload"`
	}{}
	if err := receive(r, &legacyAlerts); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	var alerts []*types.Alert
	for _, la := range legacyAlerts {
		a := &types.Alert{
			Alert: model.Alert{
				Labels:      la.Labels,
				Annotations: la.Payload,
			},
		}
		if a.Annotations == nil {
			a.Annotations = model.LabelSet{}
		}
		a.Annotations["summary"] = la.Summary
		a.Annotations["description"] = la.Description
		a.Annotations["runbook"] = la.Runbook

		alerts = append(alerts, a)
	}

	api.insertAlerts(w, r, alerts...)
}

func (api *API) addAlerts(w http.ResponseWriter, r *http.Request) {
	var alerts []*types.Alert
	if err := receive(r, &alerts); err != nil {
		respondError(w, apiError{
			typ: errorBadData,
			err: err,
		}, nil)
		return
	}

	api.insertAlerts(w, r, alerts...)
}

func (api *API) insertAlerts(w http.ResponseWriter, r *http.Request, alerts ...*types.Alert) {
	now := time.Now()

	for _, alert := range alerts {
		alert.UpdatedAt = now

		// Ensure StartsAt is set.
		if alert.StartsAt.IsZero() {
			alert.StartsAt = now
		}
		// If no end time is defined, set a timeout after which an alert
		// is marked resolved if it is not updated.
		if alert.EndsAt.IsZero() {
			alert.Timeout = true
			alert.EndsAt = now.Add(api.resolveTimeout)

			numReceivedAlerts.WithLabelValues("firing").Inc()
		} else {
			numReceivedAlerts.WithLabelValues("resolved").Inc()
		}
	}

	// Make a best effort to insert all alerts that are valid.
	var (
		validAlerts    = make([]*types.Alert, 0, len(alerts))
		validationErrs = &types.MultiError{}
	)
	for _, a := range alerts {
		if err := a.Validate(); err != nil {
			validationErrs.Add(err)
			numInvalidAlerts.Inc()
			continue
		}
		validAlerts = append(validAlerts, a)
	}
	if err := api.alerts.Put(validAlerts...); err != nil {
		respondError(w, apiError{
			typ: errorInternal,
			err: err,
		}, nil)
		return
	}

	if validationErrs.Len() > 0 {
		respondError(w, apiError{
			typ: errorBadData,
			err: validationErrs,
		}, nil)
		return
	}

	respond(w, nil)
}

func (api *API) addSilence(w http.ResponseWriter, r *http.Request) {
	var msil model.Silence
	if err := receive(r, &msil); err != nil {
		respondError(w, apiError{
			typ: errorBadData,
			err: err,
		}, nil)
		return
	}
	sil := types.NewSilence(&msil)

	if sil.CreatedAt.IsZero() {
		sil.CreatedAt = time.Now()
	}

	if err := sil.Validate(); err != nil {
		respondError(w, apiError{
			typ: errorBadData,
			err: err,
		}, nil)
		return
	}

	sid, err := api.silences.Set(sil)
	if err != nil {
		respondError(w, apiError{
			typ: errorInternal,
			err: err,
		}, nil)
		return
	}

	respond(w, struct {
		SilenceID uint64 `json:"silenceId"`
	}{
		SilenceID: sid,
	})
}

func (api *API) getSilence(w http.ResponseWriter, r *http.Request) {
	sids := route.Param(api.context(r), "sid")
	sid, err := strconv.ParseUint(sids, 10, 64)
	if err != nil {
		respondError(w, apiError{
			typ: errorBadData,
			err: err,
		}, nil)
		return
	}

	sil, err := api.silences.Get(sid)
	if err != nil {
		http.Error(w, fmt.Sprint("Error getting silence: ", err), http.StatusNotFound)
		return
	}

	respond(w, &sil)
}

func (api *API) delSilence(w http.ResponseWriter, r *http.Request) {
	sids := route.Param(api.context(r), "sid")
	sid, err := strconv.ParseUint(sids, 10, 64)
	if err != nil {
		respondError(w, apiError{
			typ: errorBadData,
			err: err,
		}, nil)
		return
	}

	if err := api.silences.Del(sid); err != nil {
		respondError(w, apiError{
			typ: errorInternal,
			err: err,
		}, nil)
		return
	}
	respond(w, nil)
}

func (api *API) listSilences(w http.ResponseWriter, r *http.Request) {
	var (
		num    = r.FormValue("n")
		offset = r.FormValue("offset")
		lastID = r.FormValue("lastID")
	)

	n, err := strconv.ParseUint(num, 10, 64)
	if err != nil {
		n = 50
	}
	o, err := strconv.ParseUint(offset, 10, 64)
	if err != nil {
		o = 0
	}
	id, err := strconv.ParseUint(lastID, 10, 64)
	if err != nil {
		id = 0
	}

	sils, err := api.silences.Query(n, o, id)
	if err != nil {
		respondError(w, apiError{
			typ: errorInternal,
			err: err,
		}, nil)
		return
	}
	respond(w, sils)
}

type status string

const (
	statusSuccess status = "success"
	statusError          = "error"
)

type response struct {
	Status    status      `json:"status"`
	Data      interface{} `json:"data,omitempty"`
	ErrorType errorType   `json:"errorType,omitempty"`
	Error     string      `json:"error,omitempty"`
}

func respond(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(200)

	b, err := json.Marshal(&response{
		Status: statusSuccess,
		Data:   data,
	})
	if err != nil {
		return
	}
	w.Write(b)
}

func respondError(w http.ResponseWriter, apiErr apiError, data interface{}) {
	w.Header().Set("Content-Type", "application/json")

	switch apiErr.typ {
	case errorBadData:
		w.WriteHeader(http.StatusBadRequest)
	case errorInternal:
		w.WriteHeader(http.StatusInternalServerError)
	default:
		panic(fmt.Sprintf("unknown error type %q", apiErr))
	}

	b, err := json.Marshal(&response{
		Status:    statusError,
		ErrorType: apiErr.typ,
		Error:     apiErr.err.Error(),
		Data:      data,
	})
	if err != nil {
		return
	}
	log.Errorf("api error: %v", apiErr)

	w.Write(b)
}

func receive(r *http.Request, v interface{}) error {
	dec := json.NewDecoder(r.Body)
	defer r.Body.Close()

	err := dec.Decode(v)
	if err != nil {
		log.Debugf("Decoding request failed: %v", err)
	}
	return err
}
