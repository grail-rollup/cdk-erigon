package types

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
	"gotest.tools/v3/assert"
)

func TestResultEncode(t *testing.T) {
	type testCase struct {
		name           string
		input          ResultEntry
		expectedResult []byte
	}
	testCases := []testCase{
		{
			name: "Happy path",
			input: ResultEntry{
				PacketType: 1,
				Length:     0,
				ErrorNum:   3,
				ErrorStr:   []byte{},
			},
			expectedResult: []byte{1, 0, 0, 0, 0, 0, 0, 0, 3},
		}, {
			name: "Error string length",
			input: ResultEntry{
				PacketType: 1,
				Length:     19,
				ErrorNum:   0,
				ErrorStr:   []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10},
			},
			expectedResult: []byte{1, 0, 0, 0, 19, 0, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			result := testCase.input.Encode()
			assert.DeepEqual(t, testCase.expectedResult, result)
		})
	}
}

func TestResultDecode(t *testing.T) {
	type testCase struct {
		name           string
		input          []byte
		expectedResult ResultEntry
		expectedError  error
	}
	testCases := []testCase{
		{
			name:  "Happy path",
			input: []byte{1, 0, 0, 0, 9, 0, 0, 0, 3},
			expectedResult: ResultEntry{
				PacketType: 1,
				Length:     9,
				ErrorNum:   3,
				ErrorStr:   []byte{},
			},
			expectedError: nil,
		}, {
			name:  "Happy path - error str length",
			input: []byte{1, 0, 0, 0, 19, 0, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10},
			expectedResult: ResultEntry{
				PacketType: 1,
				Length:     19,
				ErrorNum:   0,
				ErrorStr:   []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10},
			},
			expectedError: nil,
		},
		{
			name:           "Invalid byte array length",
			input:          []byte{20, 21, 22, 23, 24, 20},
			expectedResult: ResultEntry{},
			expectedError:  fmt.Errorf("invalid result entry binary size. Expected: >=9, got: 6"),
		},
		{
			name: "Invalid error length",
			input: ResultEntry{
				PacketType: 1,
				Length:     10,
				ErrorNum:   0,
				ErrorStr:   []byte{20, 21},
			}.Encode(),
			expectedResult: ResultEntry{},
			expectedError:  fmt.Errorf("invalid result entry error binary size. Expected: 1, got: 2"),
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			decodedResultEntry, err := DecodeResultEntry(testCase.input)
			require.Equal(t, testCase.expectedError, err)
			assert.DeepEqual(t, testCase.expectedResult, *decodedResultEntry)
		})
	}
}
