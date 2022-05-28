
# export RULE_DIR=data2
# make all
# allow to replay a set of configured/generated rules to compare rule generation
# used to test a new version of system.merge()


all: gen test compare

test:
	# move stats to remove C dependency and allow to run on linux
	echo "package stats" > ../stats/stats.go
	go test github.com/Comcast/Ravel/pkg/system -run TestCCNewMergeDir -v

gen: FORCE
	cd ${RULE_DIR}; rm 0* ; ../merge.sh; ../parse.sh

compare: FORCE
	cd ${RULE_DIR}; ../compare.sh


FORCE: ;

test2:
	TEST_OS="mac" go test -v -run TestGetDummyInterfaces
