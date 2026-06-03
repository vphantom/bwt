help:
	@echo "Available rules: build clean test test-direct test-vectors"

build:
	@dune build

clean:
	@dune clean
	@rm -fr _coverage

test:
	@rm -rf _coverage
	@if [ ! -f test-vectors.json ]; then ln -s ../test-vectors.json .; fi
	@dune runtest --profile=coverage --instrument-with bisect_ppx --force --no-buffer
	@rm ./test-vectors.json
	@bisect-ppx-report html
	@bisect-ppx-report summary
	@bisect-ppx-report coveralls _coverage/coverage.json
	@jq -r '.source_files[] | .name as $$f | .coverage | to_entries[] | select(.value == 0) | "\($$f)\t\(.key + 1)"' _coverage/coverage.json \
	  | awk -F'\t' '{ f=$$1; n=$$2; cmd="sed -n "n"p "f; cmd|getline line; close(cmd); if(f!=prev){if(prev)print"";print f":";prev=f} printf "  %4d: %s\n",n,line }' \
	  >_coverage/coverage.txt
	@echo "Coverage summary written to: _coverage/coverage.txt"

test-direct:
	@rm -rf _coverage
	@BWT_TESTS=direct dune runtest --profile=coverage --instrument-with bisect_ppx --force --no-buffer
	@bisect-ppx-report html
	@bisect-ppx-report summary
	@bisect-ppx-report coveralls _coverage/coverage.json
	@jq -r '.source_files[] | .name as $$f | .coverage | to_entries[] | select(.value == 0) | "\($$f)\t\(.key + 1)"' _coverage/coverage.json \
	  | awk -F'\t' '{ f=$$1; n=$$2; cmd="sed -n "n"p "f; cmd|getline line; close(cmd); if(f!=prev){if(prev)print"";print f":";prev=f} printf "  %4d: %s\n",n,line }' \
	  >_coverage/coverage.txt
	@echo "Coverage summary written to: _coverage/coverage.txt"

test-vectors:
	@rm -rf _coverage
	@if [ ! -f test-vectors.json ]; then ln -s ../test-vectors.json .; fi
	@BWT_TESTS=vectors dune runtest --profile=coverage --instrument-with bisect_ppx --force --no-buffer
	@rm ./test-vectors.json
	@bisect-ppx-report html
	@bisect-ppx-report summary
	@bisect-ppx-report coveralls _coverage/coverage.json
	@jq -r '.source_files[] | .name as $$f | .coverage | to_entries[] | select(.value == 0) | "\($$f)\t\(.key + 1)"' _coverage/coverage.json \
	  | awk -F'\t' '{ f=$$1; n=$$2; cmd="sed -n "n"p "f; cmd|getline line; close(cmd); if(f!=prev){if(prev)print"";print f":";prev=f} printf "  %4d: %s\n",n,line }' \
	  >_coverage/coverage.txt
	@echo "Coverage summary written to: _coverage/coverage.txt"

.PHONY: help build clean test test-direct test-vectors
