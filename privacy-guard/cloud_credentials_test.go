package main

import (
	"reflect"
	"strings"
	"testing"
)

func TestCloudCredentialExportsAndConsoleCopy(t *testing.T) {
	id := "AKIDSyntheticValue123456789_AbCd-Extra"
	key := "SyntheticAccessSecret123456/AbCd="
	session := strings.Repeat("AbCd1234_efGH5678-IjKl90+/", 40) + "="
	aliyunID := "STS.SyntheticAccessId123456789"
	for _, content := range []string{
		"export TENCENTCLOUD_SECRET_ID=\"" + id + "\"\\\nexport TENCENTCLOUD_SECRET_KEY=\"" + key + "\"\\\nexport TENCENTCLOUD_SECURITY_TOKEN=\"" + session + "\"",
		"**AccessKey ID**\n" + aliyunID + "**复制**\n**AccessKey Secret**\n" + key + "**复制**\n**SecurityToken**\n" + session + "**复制**",
	} {
		g, e := NewGateway(Config{ClientAPIKey: testClientKey, Detector: "credentials"})
		if e != nil {
			t.Fatal(e)
		}
		input := map[string]any{"messages": []any{map[string]any{"role": "user", "content": content}}}
		rec, res := postMask(t, g.Routes(), maskEnvelope(t, testMaskScope, input), testClientKey)
		if rec.Code != 200 {
			t.Fatalf("status %d", rec.Code)
		}
		for _, value := range []string{id, key, session, aliyunID} {
			if strings.Contains(content, value) && strings.Contains(string(res.Payload), value) {
				t.Fatal("credential leaked")
			}
		}
		originals := map[string]bool{}
		for _, m := range res.Mappings {
			originals[m.Original] = true
		}
		for _, value := range []string{id, key, session, aliyunID} {
			if strings.Contains(content, value) && !originals[value] {
				t.Fatal("credential was only partially masked")
			}
		}
		if !reflect.DeepEqual(input, restoreTree(mustDecode(t, res.Payload), res.Mappings)) {
			t.Fatal("round trip changed console export")
		}
	}
}

func TestCloudCredentialHeadingBoundaries(t *testing.T) {
	for _, text := range []string{"**权限**\nDBaaS-Dev-Admin-Role", "**AccessKey ID**\nThis explains a credential\nplainvalue", "AccessKey ID appears in documentation\nplainvalue"} {
		if len(cloudCredentialSpans(text)) != 0 {
			t.Fatal("ordinary label or explanation was masked")
		}
	}
	text := "**AccessKey ID**\n**AccessKey Secret**\nSyntheticSecret123**复制**"
	spans := cloudCredentialSpans(text)
	if len(spans) != 1 || text[spans[0].start:spans[0].end] != "SyntheticSecret123" {
		t.Fatal("heading or copy marker included in credential")
	}
}
