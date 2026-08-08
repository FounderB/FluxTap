.PHONY: build gen parse serve live ifaces bench test clean

build:
	go build -o fluxtap ./cmd/fluxtap

gen: build
	./fluxtap gen testdata/demo.pcap --count 500

parse: build
	./fluxtap parse testdata/demo.pcap

serve: build
	./fluxtap serve testdata/demo.pcap --addr :8090 --replay

live: build
	sudo ./fluxtap live -i any --addr :8090

ifaces: build
	./fluxtap ifaces

bench: build
	./fluxtap bench testdata/demo.pcap

test:
	go test ./...

clean:
	rm -f fluxtap pcapwow
