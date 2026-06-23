package scanner

import "testing"

func TestParseRPMQuery(t *testing.T) {
	// Tab-delimited rpm -qa --qf RPMQueryFormat output:
	// NAME \t EPOCHNUM \t VERSION-RELEASE \t ARCH \t SOURCERPM
	out := []byte("openssl-libs\t1\t3.0.7-18.el9\tx86_64\topenssl-3.0.7-18.el9.src.rpm\n" +
		"bash\t0\t5.1.8-6.el9\tx86_64\tbash-5.1.8-6.el9.src.rpm\n" +
		"gpg-pubkey\t0\tfd431d51-4ae0493b\t(none)\t(none)\n")
	pkgs := ParseRPMQuery(out)
	if len(pkgs) != 3 {
		t.Fatalf("want 3 packages, got %d: %+v", len(pkgs), pkgs)
	}

	// Epoch != 0 is prepended; source name is the bare project name.
	if pkgs[0].Name != "openssl-libs" || pkgs[0].Version != "1:3.0.7-18.el9" {
		t.Fatalf("openssl-libs parse wrong: %+v", pkgs[0])
	}
	if pkgs[0].SrcName != "openssl" {
		t.Fatalf("openssl-libs src = %q, want openssl", pkgs[0].SrcName)
	}
	// Epoch 0 must NOT be prepended.
	if pkgs[1].Version != "5.1.8-6.el9" {
		t.Fatalf("bash version = %q, want unprefixed", pkgs[1].Version)
	}
	// "(none)" SOURCERPM is not a source name.
	if pkgs[2].SrcName != "" {
		t.Fatalf("gpg-pubkey src = %q, want empty (rpm reports (none))", pkgs[2].SrcName)
	}
	if pkgs[0].PkgType != "rhel" || pkgs[0].Ecosystem != "RHEL" {
		t.Fatalf("rhel mapping wrong: %q/%q", pkgs[0].PkgType, pkgs[0].Ecosystem)
	}
}

func TestRPMSourceName(t *testing.T) {
	cases := map[string]string{
		"openssl-1.1.1k-14.el8_6.src.rpm": "openssl",
		"python3-3.6.8-1.el8.src.rpm":     "python3",
		"(none)":                          "",
		"":                                "",
	}
	for in, want := range cases {
		if got := rpmSourceName(in); got != want {
			t.Fatalf("rpmSourceName(%q) = %q, want %q", in, got, want)
		}
	}
}
