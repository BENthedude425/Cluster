package dbms

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"packages/dataTypes"
)

func ReadFile(FileName string) ([]byte, error) {
	File, err := os.Open(FileName)
	defer File.Close()

	FileSystem, err := os.Stat(FileName)

	if err != nil {
		return []byte{}, err
	}

	ContentsBuffer := make([]byte, FileSystem.Size())

	_, err = File.Read(ContentsBuffer)

	if err != nil {
		return []byte{}, err
	}

	return ContentsBuffer, err
}

func ReadTable(TableName string) ([]dataTypes.TableEntry, error) {
	var TableEntries []dataTypes.TableEntry
	FileContents, err := ReadFile(TableName)

	if len(FileContents) == 0 {
		return []dataTypes.TableEntry{}, nil
	}

	if err != nil || !json.Valid(FileContents) {
		return []dataTypes.TableEntry{}, err
	}

	err = json.Unmarshal(FileContents, &TableEntries)

	return TableEntries, err
}

func GenerateNewID(TableName string) int {
	Entries, err := ReadTable(TableName)
	NewID := 0
	FoundID := true

	if err != nil {
		log.Fatal(err)
		return 0
	}

	if len(Entries) == 0 {
		return NewID + 1
	}

	for {
		FoundID = true
		NewID++

		for i := range Entries {
			SelectedEntry := Entries[i]

			if SelectedEntry.ID == NewID {
				FoundID = false
				break
			}
		}

		if FoundID {
			return NewID
		}
	}
}

func AppendDataToTable(TableName string, Data dataTypes.TableEntry) error {
	var TableEntries []dataTypes.TableEntry
	var TableContentsBytes []byte
	TableContents, err := ReadFile(TableName)

	if err != nil {
		return err
	}

	if len(TableContents) > 0 {
		err = json.Unmarshal(TableContents, &TableEntries)

		if err != nil {
			return err
		}
	}

	TableEntries = append(TableEntries, Data)
	TableContentsBytes, err = json.MarshalIndent(TableEntries, "", "	")

	if err != nil {
		return err
	}

	err = os.WriteFile(TableName, TableContentsBytes, os.ModeAppend)
	return err
}

func FormatEntries[T dataTypes.DBDataType](TableEntries []dataTypes.TableEntry) (map[int]T, error) {
	var DataStuct T
	FormattedEntriesMap := make(map[int]T)
	for i := range TableEntries {
		SelectedEntry := TableEntries[i]

		ID := SelectedEntry.ID
		Data, err := json.Marshal(SelectedEntry.Data)

		if err != nil {
			return map[int]T{}, err
		}

		err = json.Unmarshal(Data, &DataStuct)

		if err != nil || !json.Valid(Data) {
			return map[int]T{}, fmt.Errorf("")
		}

		FormattedEntriesMap[ID-1] = DataStuct
	}

	return FormattedEntriesMap, nil
}
