.PHONY: test fmt fmt-check vet vectors vectors-check fuzz

test:
	go test ./...

fmt:
	gofmt -w .

fmt-check:
	@test -z "$$(gofmt -l .)" || { gofmt -l .; echo "Go files need formatting; run make fmt"; exit 1; }

vet:
	go vet ./...

# Regenerate testdata/noise_vectors_extended.txt with flynn/noise (needs that module available).
vectors:
	cd tools/genvectors && go run . > ../../testdata/noise_vectors_extended.txt

# Fail if the committed extended vectors differ from a fresh run of the generator.
vectors-check:
	cd tools/genvectors && go run . 2>/dev/null | cmp - ../../testdata/noise_vectors_extended.txt

# Short fuzz runs of handshake parsing and transport decryption.
fuzz:
	go test -run '^$$' -fuzz FuzzReadMessage -fuzztime 60s .
	go test -run '^$$' -fuzz FuzzDecrypt -fuzztime 30s .
