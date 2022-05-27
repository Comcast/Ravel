
# export RULE_DIR=data2
# make all
# hide stats.go : echo "package stats" > ../stats/stats.go


all: gen test compare

test:
	echo "package stats" > ../stats/stats.go
	go test github.com/Comcast/Ravel/pkg/system -run TestCCNewMergeDir -v

gen: FORCE
	cd ${RULE_DIR}; rm 0* ; ../merge.sh; ../parse.sh

compare: FORCE
	cd ${RULE_DIR}; ../compare.sh


FORCE: ;

test2:
	TEST_OS="mac" go test -v -run TestGetDummyInterfaces
