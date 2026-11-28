package main

import (
	"bytes"
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hostingsimple/paneldns-agent/internal/check"
	"github.com/hostingsimple/paneldns-agent/internal/protocol"
)

// TestUploadCheck: the uploaded report is the --check --json report
// without any zone dump; nothing is sent when not enrolled or over the
// size limit (D-35).
func TestUploadCheck(t *testing.T) {
	var sent *protocol.CheckReportRequest
	env := check.Env{Upload: func(_ context.Context, r *protocol.CheckReportRequest) (*protocol.CheckReportResponse, error) {
		sent = r
		return &protocol.CheckReportResponse{ReportID: 1}, nil
	}}
	res := &check.Result{Version: "0.1.8", Items: []check.Item{{Section: "config", Status: check.OK, Message: "config parsed"}},
		Zone: &check.ZoneDump{Name: "secret.example", Text: "never sent"}}
	if err := uploadCheck(context.Background(), env, res, protocol.CheckTriggerManual); err != nil {
		t.Fatal(err)
	}
	if sent == nil || sent.Trigger != "manual" || strings.Contains(string(sent.Report), "never sent") {
		t.Fatalf("sent %+v", sent)
	}
	var back check.Result
	if err := json.Unmarshal(sent.Report, &back); err != nil || len(back.Items) != 1 || back.Zone != nil {
		t.Fatalf("report %s %v", sent.Report, err)
	}
	if res.Zone == nil {
		t.Fatal("uploadCheck changed the caller's result")
	}

	if err := uploadCheck(context.Background(), check.Env{}, res, protocol.CheckTriggerManual); err == nil || !strings.Contains(err.Error(), "not enrolled") {
		t.Fatalf("no upload func: %v", err)
	}
	big := &check.Result{Items: []check.Item{{Message: strings.Repeat("x", protocol.MaxCheckReportBytes)}}}
	sent = nil
	if err := uploadCheck(context.Background(), env, big, protocol.CheckTriggerManual); err == nil || sent != nil {
		t.Fatalf("oversized report sent: %v", err)
	}
}

// TestCheckUploadWithZoneRefused: a zone's text is never uploaded.
func TestCheckUploadWithZoneRefused(t *testing.T) {
	stubCheckRoot(t, 1000, nil)
	var out, errb bytes.Buffer
	code := realMain([]string{"--check", "--upload", "--zone", "example.com", "--config", filepath.Join(t.TempDir(), "missing.conf")}, &out, &errb)
	if code != 2 || !strings.Contains(errb.String(), "--zone") {
		t.Fatalf("code %d, err %q", code, errb.String())
	}
}

// TestCheckUploadNotEnrolled: --upload on a server that isn't enrolled
// fails, after printing the report.
func TestCheckUploadNotEnrolled(t *testing.T) {
	stubCheckRoot(t, 1000, nil)
	var out, errb bytes.Buffer
	code := realMain([]string{"--check", "--upload", "--config", filepath.Join(t.TempDir(), "missing.conf"), "--state-dir", t.TempDir()}, &out, &errb)
	if code != 1 || !strings.Contains(out.String(), "FAIL") || !strings.Contains(errb.String(), "not enrolled") {
		t.Fatalf("code %d, out %q, err %q", code, out.String(), errb.String())
	}
}
