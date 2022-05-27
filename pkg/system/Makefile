# run our tests in a linux container
default: test

test2:
	TEST_OS="mac" go test -v -run TestGetDummyInterfaces

test:
	go test github.com/Comcast/Ravel/pkg/system -run TestCCNewMerge -v

