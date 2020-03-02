package bgp

import (
	"reflect"
	"testing"
)

/*
	example output
*/
var output = []byte(`Network              Next Hop             AS_PATH              Age        Attrs
*> 10.131.153.120/32    0.0.0.0                                   00:00:21   [{Origin: ?}]
*> 10.131.153.121/32    0.0.0.0                                   00:00:21   [{Origin: ?}]
*> 10.131.153.122/32    0.0.0.0                                   00:00:21   [{Origin: ?}]
*> 10.131.153.123/32    0.0.0.0                                   00:00:21   [{Origin: ?}]
*> 10.131.153.124/32    0.0.0.0                                   00:00:21   [{Origin: ?}]
*> 10.131.153.125/32    0.0.0.0                                   00:00:21   [{Origin: ?}]
`)

func TestParseBGPOutput(t *testing.T) {
	shouldEqual := []string{
		"10.131.153.120",
		"10.131.153.121",
		"10.131.153.122",
		"10.131.153.123",
		"10.131.153.124",
		"10.131.153.125",
	}
	outParsed := parseRIBOutput(output)

	if !reflect.DeepEqual(shouldEqual, outParsed) {
		t.Fatalf("outputs were not equal. expected %v, saw %v:", shouldEqual, outParsed)
	}
}
